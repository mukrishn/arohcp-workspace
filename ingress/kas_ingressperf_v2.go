package main

import (
	"crypto/tls"
	"encoding/json"
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

	"gopkg.in/yaml.v2"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// APISample defines a single endpoint and the number of calls to make to it.
type APISample struct {
	Endpoint string `yaml:"endpoint"`
	Samples  int    `yaml:"samples"`
}

// Config holds the configuration from the YAML file.
type Config struct {
	Loader               string      `yaml:"loader,omitempty"` // "wrk" or "vegeta"
	KubeconfigPaths      []string    `yaml:"kubeconfigs"`
	DurationStr          string      `yaml:"duration"`
	APICallSamples       []APISample `yaml:"apiCallSamples"`
	LogRequests          bool        `yaml:"logRequests"`
	LogWrkOutput         bool        `yaml:"logWrkOutput"`
	// Wrk-specific options
	Concurrency          int `yaml:"concurrency,omitempty"`
	ConnectionsPerClient int `yaml:"connectionsPerClient,omitempty"`
	// Vegeta-specific options
	Rate int `yaml:"rate,omitempty"`
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
}

// loaderReport holds the parsed performance metrics from the load generator output.
type loaderReport struct {
	ClusterName    string
	totalRequests  uint64 // Changed to uint64 for vegeta compatibility
	requestsPerSec float64
	avgLatencyMs   float64
	stdevLatencyMs float64
	maxLatencyMs   float64
	p90LatencyMs   float64
	p99LatencyMs   float64
	statusCodes    map[string]int // Changed to map[string]int for vegeta compatibility
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
	validateConfig(&cfg)

	_, err := time.ParseDuration(cfg.DurationStr)
	if err != nil {
		log.Fatalf("Error parsing duration string '%s': %v", cfg.DurationStr, err)
	}

	log.Printf("Starting kube-apiserver load test with %s...", cfg.Loader)
	log.Printf("Duration: %s", cfg.DurationStr)
	if cfg.Loader == "wrk" {
		log.Printf("Concurrency per cluster: %d, Connections per client: %d", cfg.Concurrency, cfg.ConnectionsPerClient)
	} else if cfg.Loader == "vegeta" {
		log.Printf("Rate: %d req/s", cfg.Rate)
	}

	// Build a slice of cluster configurations from the provided kubeconfig paths.
	clusterConfigs, err := buildClusterConfigs(cfg.KubeconfigPaths)
	if err != nil {
		log.Fatalf("Error building cluster configurations: %v", err)
	}
	if len(clusterConfigs) == 0 {
		log.Fatal("No valid cluster configurations found.")
	}
	log.Printf("Starting test on %d cluster(s).\n", len(clusterConfigs))

	// Create and bind service accounts for each cluster.
	for i := range clusterConfigs {
		log.Printf("Creating service account and role binding for cluster '%s'", clusterConfigs[i].name)
		if err := createServiceAccount(&clusterConfigs[i]); err != nil {
			log.Fatalf("Failed to create service account for cluster '%s': %v", clusterConfigs[i].name, err)
		}
	}

	defer func() {
		for _, config := range clusterConfigs {
			cleanupServiceAccount(config)
		}
	}()

	preFlightCheck(clusterConfigs)

	reportsChan := make(chan loaderReport, len(clusterConfigs))

	// Run tests using the selected loader.
	runLoadTests(clusterConfigs, cfg, reportsChan)

	log.Println("Load test finished. Aggregating results...")
	wg.Wait()
	close(reportsChan)

	reports := make(map[string]loaderReport)
	for report := range reportsChan {
		reports[report.ClusterName] = report
	}

	writeJSONReport("report.json", reports)
}

func validateConfig(cfg *Config) {
	if cfg.Loader == "" {
		cfg.Loader = "wrk"
	}

	if cfg.Loader == "wrk" {
		if cfg.ConnectionsPerClient == 0 {
			cfg.ConnectionsPerClient = 1
		}
		if cfg.Concurrency == 0 {
			log.Fatal("Error: 'concurrency' must be set for the 'wrk' loader.")
		}
	} else if cfg.Loader == "vegeta" {
		if cfg.Rate == 0 {
			log.Fatal("Error: 'rate' must be set for the 'vegeta' loader.")
		}
	} else {
		log.Fatalf("Error: Unknown loader '%s'. Please use 'wrk' or 'vegeta'.", cfg.Loader)
	}
}

// runLoadTests orchestrates the load test for all clusters.
func runLoadTests(clusterConfigs []clusterConfig, cfg Config, reportsChan chan<- loaderReport) {
	for _, config := range clusterConfigs {
		wg.Add(1)
		go func(config clusterConfig) {
			defer wg.Done()
			var report loaderReport
			var err error

			switch cfg.Loader {
			case "wrk":
				report, err = runSingleWrkTest(config, cfg)
			case "vegeta":
				report, err = runSingleVegetaTest(config, cfg)
			}

			if err != nil {
				log.Printf("Test for cluster '%s' failed: %v", config.name, err)
				reportsChan <- loaderReport{ClusterName: config.name, statusCodes: map[string]int{"0": 0}}
			} else {
				report.ClusterName = config.name
				reportsChan <- report
				log.Printf("Test for cluster '%s' completed.", config.name)
			}
		}(config)
	}
}

// NEW: sanitizeFilename replaces characters that are invalid in filenames.
func sanitizeFilename(name string) string {
	r := strings.NewReplacer("://", "_", "/", "_", ":", "_")
	return r.Replace(name)
}

// runSingleWrkTest executes a load test using 'wrk'.
func runSingleWrkTest(config clusterConfig, cfg Config) (loaderReport, error) {
	log.Printf("Starting wrk test for cluster '%s'...", config.name)
	luaScript := buildWrkScript(cfg.APICallSamples)
	scriptFile, err := os.CreateTemp("", "wrk-script-*.lua")
	if err != nil {
		return loaderReport{}, fmt.Errorf("failed to create temp Lua script: %w", err)
	}
	defer os.Remove(scriptFile.Name())
	if _, err := scriptFile.WriteString(luaScript); err != nil {
		return loaderReport{}, fmt.Errorf("failed to write Lua script: %w", err)
	}
	scriptFile.Close()

	args := []string{
		"-d", cfg.DurationStr,
		"-c", fmt.Sprintf("%d", cfg.ConnectionsPerClient),
		"-t", fmt.Sprintf("%d", cfg.Concurrency),
		"--header", fmt.Sprintf("Authorization: Bearer %s", config.bearerToken),
		"-s", scriptFile.Name(),
		config.apiServer,
		"--latency",
	}

	cmd := exec.Command("wrk", args...)
	log.Printf("Executing command for cluster '%s': wrk %s", config.name, strings.Join(args, " "))
	output, err := cmd.CombinedOutput()

	// *** MODIFIED: Save raw output to a file ***
	sanitizedName := sanitizeFilename(config.name)
	outputFilename := fmt.Sprintf("wrk_output_%s.log", sanitizedName)
	if writeErr := os.WriteFile(outputFilename, output, 0644); writeErr != nil {
		log.Printf("Warning: failed to write raw wrk output to %s: %v", outputFilename, writeErr)
	} else {
		log.Printf("Raw wrk output for cluster '%s' saved to %s", config.name, outputFilename)
	}

	if err != nil {
		return loaderReport{}, fmt.Errorf("%w\nOutput: %s", err, string(output))
	}

	if cfg.LogWrkOutput {
		log.Printf("-- wrk output --\n%s\n-- end wrk output --", string(output))
	}

	return parseWrkOutput(output), nil
}

// runSingleVegetaTest executes a load test using 'vegeta'.
func runSingleVegetaTest(config clusterConfig, cfg Config) (loaderReport, error) {
	log.Printf("Starting vegeta test for cluster '%s'...", config.name)
	targetsFile, err := buildVegetaTargets(cfg.APICallSamples, config.apiServer, config.bearerToken)
	if err != nil {
		return loaderReport{}, fmt.Errorf("failed to create vegeta targets file: %w", err)
	}
	defer os.Remove(targetsFile)

	attackCmd := fmt.Sprintf("vegeta attack -targets=%s -rate=%d -duration=%s -insecure", targetsFile, cfg.Rate, cfg.DurationStr)
	reportCmd := "vegeta report -type=json"
	fullCmd := attackCmd + " | " + reportCmd

	log.Printf("Executing command for cluster '%s': %s", config.name, fullCmd)
	cmd := exec.Command("sh", "-c", fullCmd)
	output, err := cmd.CombinedOutput()

	// *** MODIFIED: Save raw output to a file ***
	sanitizedName := sanitizeFilename(config.name)
	outputFilename := fmt.Sprintf("vegeta_output_%s.log", sanitizedName)
	if writeErr := os.WriteFile(outputFilename, output, 0644); writeErr != nil {
		log.Printf("Warning: failed to write raw vegeta output to %s: %v", outputFilename, writeErr)
	} else {
		log.Printf("Raw vegeta output for cluster '%s' saved to %s", config.name, outputFilename)
	}

	if err != nil {
		return loaderReport{}, fmt.Errorf("%w\nOutput: %s", err, string(output))
	}

	if cfg.LogWrkOutput {
		log.Printf("-- vegeta output --\n%s\n-- end vegeta output --", string(output))
	}

	return parseVegetaOutput(output)
}

// buildVegetaTargets creates a temporary file with targets for vegeta.
func buildVegetaTargets(samples []APISample, apiServer, token string) (string, error) {
	targetFile, err := os.CreateTemp("", "vegeta-targets-*.txt")
	if err != nil {
		return "", err
	}
	defer targetFile.Close()

	var builder strings.Builder
	for _, sample := range samples {
		for i := 0; i < sample.Samples; i++ {
			builder.WriteString(fmt.Sprintf("GET %s%s\n", apiServer, sample.Endpoint))
			builder.WriteString(fmt.Sprintf("Authorization: Bearer %s\n", token))
			builder.WriteString("Accept: application/json\n\n") // Two newlines separate targets
		}
	}

	if _, err := targetFile.WriteString(builder.String()); err != nil {
		return "", err
	}
	return targetFile.Name(), nil
}

// VegetaJSONReport defines the structure for vegeta's JSON output.
type VegetaJSONReport struct {
	Latencies struct {
		Total  time.Duration `json:"total"`
		Mean   time.Duration `json:"mean"`
		P50    time.Duration `json:"50th"`
		P90    time.Duration `json:"90th"`
		P95    time.Duration `json:"95th"`
		P99    time.Duration `json:"99th"`
		Max    time.Duration `json:"max"`
		Min    time.Duration `json:"min"`
	} `json:"latencies"`
	Requests    uint64         `json:"requests"`
	Rate        float64        `json:"rate"`
	StatusCodes map[string]int `json:"status_codes"`
}

// parseVegetaOutput parses the JSON output from vegeta.
func parseVegetaOutput(output []byte) (loaderReport, error) {
	var vegetaData VegetaJSONReport
	if err := json.Unmarshal(output, &vegetaData); err != nil {
		return loaderReport{}, fmt.Errorf("failed to unmarshal vegeta JSON: %w", err)
	}

	report := loaderReport{
		totalRequests:  vegetaData.Requests,
		requestsPerSec: vegetaData.Rate,
		avgLatencyMs:   float64(vegetaData.Latencies.Mean.Nanoseconds()) / 1e6,
		maxLatencyMs:   float64(vegetaData.Latencies.Max.Nanoseconds()) / 1e6,
		p90LatencyMs:   float64(vegetaData.Latencies.P90.Nanoseconds()) / 1e6,
		p99LatencyMs:   float64(vegetaData.Latencies.P99.Nanoseconds()) / 1e6,
		statusCodes:    vegetaData.StatusCodes,
		stdevLatencyMs: 0, // Vegeta's default report doesn't include stdev
	}

	return report, nil
}

// parseWrkOutput parses the text output from wrk.
func parseWrkOutput(output []byte) loaderReport {
	report := loaderReport{
		statusCodes: make(map[string]int),
	}
	outputStr := string(output)

	requestsRegex := regexp.MustCompile(`Req/Sec\s+([\d.]+)`)
	requestsCountRegex := regexp.MustCompile(`(\d+) requests in`)
	if match := requestsCountRegex.FindStringSubmatch(outputStr); len(match) > 1 {
		fmt.Sscanf(match[1], "%d", &report.totalRequests)
	}
	if match := requestsRegex.FindStringSubmatch(outputStr); len(match) > 1 {
		fmt.Sscanf(match[1], "%f", &report.requestsPerSec)
	}

	latencyRegex := regexp.MustCompile(`Latency\s+([\d.]+)(\S+)\s+([\d.]+)(\S+)\s+([\d.]+)(\S+)`)
	if match := latencyRegex.FindStringSubmatch(outputStr); len(match) > 6 {
		var avg, stdev, max float64
		fmt.Sscanf(match[1], "%f", &avg)
		report.avgLatencyMs = parseDurationToMs(avg, match[2])
		fmt.Sscanf(match[3], "%f", &stdev)
		report.stdevLatencyMs = parseDurationToMs(stdev, match[4])
		fmt.Sscanf(match[5], "%f", &max)
		report.maxLatencyMs = parseDurationToMs(max, match[6])
	}

	p90Regex := regexp.MustCompile(`\s+90%\s+([\d.]+)(\S+)`)
	if match := p90Regex.FindStringSubmatch(outputStr); len(match) > 2 {
		var p90 float64
		fmt.Sscanf(match[1], "%f", &p90)
		report.p90LatencyMs = parseDurationToMs(p90, match[2])
	}

	p99Regex := regexp.MustCompile(`\s+99%\s+([\d.]+)(\S+)`)
	if match := p99Regex.FindStringSubmatch(outputStr); len(match) > 2 {
		var p99 float64
		fmt.Sscanf(match[1], "%f", &p99)
		report.p99LatencyMs = parseDurationToMs(p99, match[2])
	}

	statusCodesRegex := regexp.MustCompile(`\[(\d+)]\s+(\d+)`)
	for _, match := range statusCodesRegex.FindAllStringSubmatch(outputStr, -1) {
		var count int
		fmt.Sscanf(match[2], "%d", &count)
		report.statusCodes[match[1]] = count // Use string key for status code
	}

	return report
}

// writeJSONReport formats the test report into a JSON object and writes it to a file.
func writeJSONReport(filename string, reports map[string]loaderReport) {
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Error creating JSON file: %v", err)
		return
	}
	defer file.Close()

	var finalReports []map[string]interface{}
	for clusterName, report := range reports {
		finalReports = append(finalReports, map[string]interface{}{
			"Cluster":            clusterName,
			"Total Requests":     report.totalRequests,
			"Requests/sec":       report.requestsPerSec,
			"Avg Latency (ms)":   report.avgLatencyMs,
			"Stdev Latency (ms)": report.stdevLatencyMs,
			"Max Latency (ms)":   report.maxLatencyMs,
			"P90 Latency (ms)":   report.p90LatencyMs,
			"P99 Latency (ms)":   report.p99LatencyMs,
			"StatusCodes":        report.statusCodes,
		})
	}

	jsonData, err := json.MarshalIndent(finalReports, "", "  ")
	if err != nil {
		log.Printf("Error marshalling JSON: %v", err)
		return
	}

	if _, err := file.Write(jsonData); err != nil {
		log.Printf("Error writing JSON to file: %v", err)
	}

	log.Printf("Successfully wrote report to %s", filename)
}

// --- Unchanged Helper Functions ---

func loadConfig(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, cfg)
}

func buildClusterConfigs(kubeconfigPaths []string) ([]clusterConfig, error) {
	if len(kubeconfigPaths) == 0 {
		if home := homedir.HomeDir(); home != "" {
			kubeconfigPaths = []string{fmt.Sprintf("%s/.kube/config", home)}
		} else {
			return nil, fmt.Errorf("could not find kubeconfig path")
		}
	}
	var configs []clusterConfig
	for _, path := range kubeconfigPaths {
		path = strings.TrimSpace(path)
		clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: path}, &clientcmd.ConfigOverrides{})
		restConfig, err := clientConfig.ClientConfig()
		if err != nil {
			log.Printf("Warning: Skipping kubeconfig '%s' due to error: %v", path, err)
			continue
		}
		configs = append(configs, clusterConfig{
			name:           restConfig.Host,
			apiServer:      restConfig.Host,
			kubeconfigPath: path,
		})
	}
	return configs, nil
}

func createServiceAccount(config *clusterConfig) error {
	saName := "kube-burner-sa"
	namespace := "default"
	createSACmd := exec.Command("kubectl", "create", "sa", saName, "-n", namespace, "--kubeconfig", config.kubeconfigPath)
	if output, err := createSACmd.CombinedOutput(); err != nil && !strings.Contains(string(output), "already exists") {
		return fmt.Errorf("failed to create ServiceAccount: %s", string(output))
	}
	crbName := "my-api-reader"
	createCRBCmd := exec.Command("kubectl", "create", "clusterrolebinding", crbName, "--clusterrole=cluster-admin", "--serviceaccount", fmt.Sprintf("%s:%s", namespace, saName), "--kubeconfig", config.kubeconfigPath)
	if output, err := createCRBCmd.CombinedOutput(); err != nil && !strings.Contains(string(output), "already exists") {
		return fmt.Errorf("failed to create ClusterRoleBinding: %s", string(output))
	}
	token, err := generateTokenWithKubectl(config.kubeconfigPath, namespace, saName)
	if err != nil {
		return fmt.Errorf("failed to get token for new ServiceAccount: %w", err)
	}
	config.serviceAccountName = saName
	config.bearerToken = token
	return nil
}

func cleanupServiceAccount(config clusterConfig) {
	namespace := "default"
	saName := "kube-burner-sa"
	crbName := "my-api-reader"
	log.Printf("Cleaning up resources for cluster '%s'...", config.name)
	deleteCRBCmd := exec.Command("kubectl", "delete", "clusterrolebinding", crbName, "--kubeconfig", config.kubeconfigPath, "--ignore-not-found")
	if output, err := deleteCRBCmd.CombinedOutput(); err != nil {
		log.Printf("Warning: Failed to delete ClusterRoleBinding '%s': %s", crbName, string(output))
	}
	deleteSACmd := exec.Command("kubectl", "delete", "sa", saName, "-n", namespace, "--kubeconfig", config.kubeconfigPath, "--ignore-not-found")
	if output, err := deleteSACmd.CombinedOutput(); err != nil {
		log.Printf("Warning: Failed to delete ServiceAccount '%s': %s", saName, string(output))
	}
	log.Printf("Cleanup complete for cluster '%s'.", config.name)
}

func generateTokenWithKubectl(kubeconfigPath, namespace, saName string) (string, error) {
	cmd := exec.Command("kubectl", "create", "token", saName, "-n", namespace, "--kubeconfig", kubeconfigPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to create token: %s", string(output))
	}
	return strings.TrimSpace(string(output)), nil
}

func preFlightCheck(clusterConfigs []clusterConfig) {
	log.Println("Performing pre-flight checks on all clusters...")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 5 * time.Second}
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
			log.Fatalf("Pre-flight check failed for cluster '%s': %v", config.name, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			log.Fatalf("Pre-flight check failed for cluster '%s': status %d. Response: %s", config.name, resp.StatusCode, string(body))
		}
		log.Printf("Pre-flight check passed for cluster '%s'", config.name)
	}
}

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
	script.WriteString("request = function()\n")
	script.WriteString("  local index = math.random(1, #endpoints)\n")
	script.WriteString("  return wrk.format('GET', endpoints[index])\n")
	script.WriteString("end\n")
	return script.String()
}
