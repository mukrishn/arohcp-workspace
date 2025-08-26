package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
	"crypto/tls"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"gopkg.in/yaml.v2"
)

// APISample defines a single endpoint and the number of calls to make to it.
type APISample struct {
	Endpoint string `yaml:"endpoint"`
	Samples  int    `yaml:"samples"`
}

// Config holds the configuration from the YAML file.
type Config struct {
	KubeconfigPaths []string      `yaml:"kubeconfigs"`
	DurationStr     string `yaml:"duration"`
	Concurrency     int           `yaml:"concurrency"`
	ConnectionsPerClient int           `yaml:"connectionsPerClient"`
	APICallSamples  []APISample   `yaml:"apiCallSamples"`
	LogRequests     bool          `yaml:"logRequests"`
	ServiceAccount  string        `yaml:"serviceAccount"`
	LogWrkOutput    bool          `yaml:"logWrkOutput"`
}

// Define command-line flags for configuration.
var (
	configPath = flag.String("config", "config.yaml", "Path to the configuration file.")
)

// clusterConfig holds the necessary information to connect to a single cluster.
type clusterConfig struct {
	name               string
	apiServer          string
	bearerToken        string
	kubeconfigPath     string
	serviceAccountName string
	tokenMutex         sync.Mutex
	clientCfg          clientcmd.ClientConfig
}

// wrkReport holds the parsed performance metrics from the wrk command output.
type wrkReport struct {
	ClusterName string
	totalRequests int
	requestsPerSec float64
	avgLatencyMs float64
	stdevLatencyMs float64
	maxLatencyMs float64
	statusCodes map[int]int
}

// Global variables for a simple performance report.
var wg sync.WaitGroup

func main() {
	flag.Parse()

	// Load configuration from the YAML file.
	var cfg Config
	if err := loadConfig(*configPath, &cfg); err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Set default for connectionsPerClient if not specified
	if cfg.ConnectionsPerClient == 0 {
		cfg.ConnectionsPerClient = 1
	}
	if cfg.ServiceAccount == "" {
		cfg.ServiceAccount = "default:default"
	}
	
	duration, err := time.ParseDuration(cfg.DurationStr)
	if err != nil {
		log.Fatalf("Error parsing duration string: %v", err)
	}

	// Build a slice of cluster configurations from the provided kubeconfig paths.
	clusterConfigs, err := buildClusterConfigs(cfg.KubeconfigPaths, cfg.ServiceAccount)
	if err != nil {
		log.Fatalf("Error building cluster configurations: %v", err)
	}
	if len(clusterConfigs) == 0 {
		log.Fatal("No valid cluster configurations found.")
	}
	log.Printf("Starting test on %d cluster(s).\n", len(clusterConfigs))

	// Perform a pre-flight check on all clusters before starting the load test
	preFlightCheck(clusterConfigs)

	// Channel to receive reports from each cluster's wrk test
	wrkReports := make(chan wrkReport, len(clusterConfigs))
	
	// Create and run a worker pool for each cluster.
	runWrkTests(clusterConfigs, cfg, wrkReports)

	log.Println("Load test finished. Aggregating results...")

	// Wait for all workers to finish before closing the results channel.
	wg.Wait()
	close(wrkReports)

	// Collect reports and write to CSV
	reports := make(map[string]wrkReport)
	for report := range wrkReports {
		reports[report.ClusterName] = report
	}

	// Print the final report to stdout
	fmt.Printf("\n--- Final Load Test Report ---\n")
	
	for _, config := range clusterConfigs {
		report, ok := reports[config.name]
		if !ok || report.totalRequests == 0 {
			fmt.Printf("\nReport for cluster '%s':\n", config.name)
			fmt.Printf("  No requests were completed.\n")
			continue
		}

		fmt.Printf("\nReport for cluster '%s':\n", config.name)
		fmt.Printf("  Total Requests: %d\n", report.totalRequests)
		fmt.Printf("  Requests/sec: %.2f\n", report.requestsPerSec)
		fmt.Printf("  Avg Latency: %.2fms\n", report.avgLatencyMs)
		fmt.Printf("  Stdev Latency: %.2fms\n", report.stdevLatencyMs)
		fmt.Printf("  Max Latency: %.2fms\n", report.maxLatencyMs)
		fmt.Printf("  Status Codes:\n")
		for code, count := range report.statusCodes {
			fmt.Printf("    - %d: %d\n", code, count)
		}
	}

	// Write the final report to a CSV file.
	writeCSVReport("report.csv", reports, clusterConfigs, cfg, duration.Seconds())
}

// loadConfig reads and parses the YAML configuration file.
func loadConfig(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, cfg)
}

// getRefreshedToken is a thread-safe method to get a new bearer token from the kubeconfig.
func (c *clusterConfig) getRefreshedToken() (string, error) {
	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()

	saParts := strings.SplitN(c.serviceAccountName, ":", 2)
	namespace := saParts[0]
	saName := saParts[1]

	token, err := generateTokenWithKubectl(c.kubeconfigPath, namespace, saName)
	if err != nil {
		return "", fmt.Errorf("failed to refresh token: %w", err)
	}

	c.bearerToken = token
	return c.bearerToken, nil
}


// buildClusterConfigs loads details from a list of kubeconfig files.
func buildClusterConfigs(kubeconfigPaths []string, serviceAccount string) ([]clusterConfig, error) {
	if len(kubeconfigPaths) == 0 {
		// Default to ~/.kube/config if no paths are specified.
		if home := homedir.HomeDir(); home != "" {
			kubeconfigPaths = []string{fmt.Sprintf("%s/.kube/config", home)}
		} else {
			return nil, fmt.Errorf("could not find kubeconfig path")
		}
	}

	var configs []clusterConfig
	for _, path := range kubeconfigPaths {
		path = strings.TrimSpace(path)

		// Use NewNonInteractiveDeferredLoadingClientConfig to handle all auth types.
		// This is the most reliable way to get a configured client with a token.
		clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: path},
			&clientcmd.ConfigOverrides{},
		)

		// Build the rest.Config object
		restConfig, err := clientConfig.ClientConfig()
		if err != nil {
			log.Printf("Warning: Skipping kubeconfig '%s' due to error: %v", path, err)
			continue
		}

		// Initial token generation using kubectl
		saParts := strings.SplitN(serviceAccount, ":", 2)
		if len(saParts) != 2 {
			log.Printf("Warning: Skipping kubeconfig '%s' as invalid service account format: %s", path, serviceAccount)
			continue
		}
		namespace := saParts[0]
		saName := saParts[1]

		token, err := generateTokenWithKubectl(path, namespace, saName)
		if err != nil {
			log.Printf("Warning: Skipping kubeconfig '%s' as initial token generation failed: %v", path, err)
			continue
		}

		configs = append(configs, clusterConfig{
			name: restConfig.Host,
			apiServer: restConfig.Host,
			bearerToken: token,
			kubeconfigPath: path,
			serviceAccountName: serviceAccount,
			clientCfg: clientConfig,
		})
	}

	return configs, nil
}

// generateTokenWithKubectl fetches a token for a service account using kubectl.
// NOTE: This requires the user in the kubeconfig to have 'create' verb on 'TokenReviews'
func generateTokenWithKubectl(kubeconfigPath, namespace, saName string) (string, error) {
	cmd := exec.Command("kubectl", "create", "token", saName, "-n", namespace, "--kubeconfig", kubeconfigPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to create token for service account '%s/%s': %s", namespace, saName, string(output))
	}

	return strings.TrimSpace(string(output)), nil
}

// preFlightCheck verifies authentication and connectivity for each cluster.
func preFlightCheck(clusterConfigs []clusterConfig) {
	log.Println("Performing pre-flight checks on all clusters...")
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
	}

	for _, config := range clusterConfigs {
		url := fmt.Sprintf("%s/api", config.apiServer)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Fatalf("Failed to create pre-flight request for cluster '%s': %v", config.name, err)
		}

		req.Header.Set("Authorization", "Bearer "+config.bearerToken)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Pre-flight check failed for cluster '%s': failed to connect to API server at %s. Error: %v", config.name, url, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			log.Fatalf("Pre-flight check failed for cluster '%s': received non-200 status code %d. Response: %s", config.name, resp.StatusCode, string(body))
		}

		log.Printf("Pre-flight check passed for cluster '%s'", config.name)
	}
}

// runWrkTests orchestrates the wrk command for all clusters concurrently.
func runWrkTests(clusterConfigs []clusterConfig, cfg Config, wrkReports chan<- wrkReport) {
	for _, config := range clusterConfigs {
		wg.Add(1)
		go func(config clusterConfig) {
			defer wg.Done()
			log.Printf("Starting wrk test for cluster '%s'...", config.name)
			
			// Build the Lua script string from the APICallSamples
			luaScript := buildWrkScript(cfg.APICallSamples)
			scriptFile, err := os.CreateTemp("", "wrk-script-*.lua")
			if err != nil {
				log.Printf("Failed to create temp Lua script for cluster '%s': %v", config.name, err)
				wrkReports <- wrkReport{ClusterName: config.name, statusCodes: map[int]int{0: 0}}
				return
			}
			defer os.Remove(scriptFile.Name())
			if _, err := scriptFile.WriteString(luaScript); err != nil {
				log.Printf("Failed to write Lua script for cluster '%s': %v", config.name, err)
				wrkReports <- wrkReport{ClusterName: config.name, statusCodes: map[int]int{0: 0}}
				return
			}
			scriptFile.Close()

			// Build the wrk command
			args := []string{
				"-d", cfg.DurationStr,
				"-c", fmt.Sprintf("%d", cfg.ConnectionsPerClient),
				"-t", fmt.Sprintf("%d", cfg.Concurrency),
				"--header", fmt.Sprintf("Authorization: Bearer %s", config.bearerToken),
				"-s", scriptFile.Name(),
				config.apiServer,
			}
			
			cmd := exec.Command("wrk", args...)
			log.Printf("Executing command for cluster '%s': wrk %s", config.name, strings.Join(args, " "))
			output, err := cmd.CombinedOutput()
			if err != nil {
				log.Printf("Wrk test for cluster '%s' failed: %v\nOutput: %s", config.name, err, string(output))
				// Send a report with no metrics, just the cluster name
				wrkReports <- wrkReport{ClusterName: config.name, statusCodes: map[int]int{0: 0}}
				return
			}
			
			if cfg.LogWrkOutput {
				log.Println("--- wrk output ---")
				log.Println(string(output))
				log.Println("--- end wrk output ---")
			}

			// Parse and report the wrk output
			report := parseWrkOutput(output)
			report.ClusterName = config.name
			wrkReports <- report
			log.Printf("Wrk test for cluster '%s' completed.", config.name)

		}(config)
	}
}

// buildWrkScript generates a Lua script for wrk based on the configured API call samples.
func buildWrkScript(samples []APISample) string {
	var script strings.Builder
	script.WriteString("math.randomseed(os.time())\n\n")
	script.WriteString("local endpoints = {\n")
	for _, sample := range samples {
		for i := 0; i < sample.Samples; i++ {
			script.WriteString(fmt.Sprintf("  \"%s\",\n", sample.Endpoint))
		}
	}
	script.WriteString("}\n\n")
	script.WriteString("local function weighted_random_endpoint()\n")
	script.WriteString("  local index = math.random(1, #endpoints)\n")
	script.WriteString("  return endpoints[index]\n")
	script.WriteString("end\n\n")
	script.WriteString("request = function()\n")
	script.WriteString("  return wrk.format('GET', weighted_random_endpoint())\n")
	script.WriteString("end\n")
	
	return script.String()
}

// parseWrkOutput parses the wrk command output and extracts key metrics.
func parseWrkOutput(output []byte) wrkReport {
	report := wrkReport{
		statusCodes: make(map[int]int),
	}
	outputStr := string(output)

	// Regex to find total requests and RPS
	requestsRegex := regexp.MustCompile(`Req/Sec\s+([\d.]+)`)
	requestsCountRegex := regexp.MustCompile(`(\d+) requests in`)

	if match := requestsCountRegex.FindStringSubmatch(outputStr); len(match) > 1 {
		fmt.Sscanf(match[1], "%d", &report.totalRequests)
	}
	if match := requestsRegex.FindStringSubmatch(outputStr); len(match) > 1 {
		fmt.Sscanf(match[1], "%f", &report.requestsPerSec)
	}
	
	// Regex to find latency average, stdev, and max
	latencyRegex := regexp.MustCompile(`Latency\s+([\d.]+)(\S+)\s+([\d.]+)(\S+)\s+([\d.]+)(\S+)\s+`)
	if match := latencyRegex.FindStringSubmatch(outputStr); len(match) > 6 {
		// Capture average latency and unit
		var avg float64
		fmt.Sscanf(match[1], "%f", &avg)
		report.avgLatencyMs = parseDurationToMs(avg, match[2])
		
		// Capture stdev latency and unit
		var stdev float64
		fmt.Sscanf(match[3], "%f", &stdev)
		report.stdevLatencyMs = parseDurationToMs(stdev, match[4])
		
		// Capture max latency and unit
		var max float64
		fmt.Sscanf(match[5], "%f", &max)
		report.maxLatencyMs = parseDurationToMs(max, match[6])
	} else {
		// Fallback for different output formats that might not include stdev/max
		latencyRegex := regexp.MustCompile(`\s*(\d+\.\d+)ms\s*(\d+\.\d+)ms\s*(\d+\.\d+)ms`)
		if matches := latencyRegex.FindAllStringSubmatch(outputStr, -1); len(matches) > 0 {
			if len(matches) >= 3 {
				fmt.Sscanf(matches[0][1], "%f", &report.avgLatencyMs)
				fmt.Sscanf(matches[2][1], "%f", &report.stdevLatencyMs)
				fmt.Sscanf(matches[3][1], "%f", &report.maxLatencyMs)
			}
		}
	}

	// Regex to find status code counts
	statusCodesRegex := regexp.MustCompile(`\[(\d+)]\s+(\d+)`)
	for _, match := range statusCodesRegex.FindAllStringSubmatch(outputStr, -1) {
		var code, count int
		fmt.Sscanf(match[1], "%d", &code)
		fmt.Sscanf(match[2], "%d", &count)
		report.statusCodes[code] = count
	}

	return report
}

// parseDurationToMs converts a float and a unit string into a float64 representing milliseconds.
func parseDurationToMs(val float64, unit string) float64 {
	switch unit {
	case "us":
		return val / 1000
	case "ms":
		return val
	case "s":
		return val * 1000
	default:
		return 0
	}
}


// writeCSVReport generates a CSV file with the load test report.
func writeCSVReport(filename string, reports map[string]wrkReport, clusterConfigs []clusterConfig, cfg Config, durationSeconds float64) {
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Error creating CSV file: %v", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write the header row
	header := []string{"Cluster", "Total Requests", "Requests/sec", "Avg Latency (ms)", "Stdev Latency (ms)", "Max Latency (ms)", "Status Code", "Count", "Concurrency", "ConnectionsPerClient", "Duration(s)"}
	if err := writer.Write(header); err != nil {
		log.Printf("Error writing CSV header: %v", err)
		return
	}

	for _, config := range clusterConfigs {
		report, ok := reports[config.name]
		if !ok || report.totalRequests == 0 {
			writer.Write([]string{config.name, "0", "0", "0", "0", "0", "N/A", "0", fmt.Sprintf("%d", cfg.Concurrency), fmt.Sprintf("%d", cfg.ConnectionsPerClient), fmt.Sprintf("%.0f", durationSeconds)})
			continue
		}
		
		for code, count := range report.statusCodes {
			row := []string{
				config.name,
				fmt.Sprintf("%d", report.totalRequests),
				fmt.Sprintf("%.2f", report.requestsPerSec),
				fmt.Sprintf("%.2f", report.avgLatencyMs),
				fmt.Sprintf("%.2f", report.stdevLatencyMs),
				fmt.Sprintf("%.2f", report.maxLatencyMs),
				fmt.Sprintf("%d", code),
				fmt.Sprintf("%d", count),
				fmt.Sprintf("%d", cfg.Concurrency),
				fmt.Sprintf("%d", cfg.ConnectionsPerClient),
				fmt.Sprintf("%.0f", durationSeconds),
			}
			if err := writer.Write(row); err != nil {
				log.Printf("Error writing CSV row: %v", err)
				return
			}
		}
	}
	log.Printf("Successfully wrote report to %s", filename)
}
