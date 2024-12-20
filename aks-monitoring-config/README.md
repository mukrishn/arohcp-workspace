# AMA monitoring config

## AMA configuration
* Configure AKS monitoring from the Azure portal 
* Apply the configmap - `ama-metrics-settings-configmap.yaml`

# AKS Prometheus operator deployment 

## Install operator 
* Clone https://github.com/prometheus-operator/kube-prometheus.git
* Install Kube-prometheus-stack following this https://github.com/prometheus-operator/kube-prometheus?tab=readme-ov-file#quickstart
* Make sure they are up and running
* Move them to system agentpool manually by editing `prometheus` and `alertmanager` CRD in `monitoring` namespace and the below selector and tolerations to it.
  ```
  nodeSelector:
    agentpool: system
  tolerations:
  - key: CriticalAddonsOnly
    operator: Exists
  ```
* Also remove resource limits from node-exporter as they often need more memory at scale and kubelet would kill it when OOM.

## Configure to scrape from servicemonitors
* By default Prometheus will scrape metrics from `default`, `kube-system`, `monitoring` namespaces
* In order to include additional servicemonitors, it needs privileges to access them
* Create `prometheus-roleSpecificNamespaces.yaml` and `prometheus-roleBindingSpecificNamespaces.yaml` - example include `hypershift` and `cluster-aks-hosted-cp` namespaces only
* Also label `monitoring` namespace to allow HCP scrapping from external namespace - `k label ns monitoring network.openshift.io/policy-group=monitoring
`
* For every new HCP namespace we need to create this role and role binding post hostedcluster creation
* Watch prometheus-k8s logs, to see if they start scraping metrics from these additional namespace
  

## Access it externally
* Expose prometheus-k8s publicly using `Loadbalancer` service type
* Create `prom-public-svc.yaml` - creates a service
* Delete the prometheus-k8s network policy in order to allow all external traffic to query  metrics
* `kubectl delete networkpolicy -n monitoring prometheus-k8s`
* Try curl using the Loadbalancer IP
```
bash-5.2# curl -k "http://10.0.223.31:9090/api/v1/query?query=sum(etcd_requests_total)by(namespace)"
{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"default"},"value":[1715176072.599,"404828"]},{"metric":{"namespace":"clusters-aks-hosted-cp-1"},"value":[1715176072.599,"147178"]},{"metric":{"namespace":"clusters-aks-hosted-cp-3"},"value":[1715176072.599,"105547"]}]}}
```

## Run a workload
* Git clone e2e benchmarking workload

```
export AZURE_PROM=https://managed-azure-prometheus.azure.com
export AKS_PROM=http://10.0.223.31:9090
export AZURE_PROM_TOKEN=$(curl --request POST 'https://login.microsoftonline.com/tenantidforazure/oauth2/v2.0/token' --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'client_id=clientidforazure' --data-urlencode 'grant_type=client_credentials' --data-urlencode 'client_secret=secrettoeknforazure' --data-urlencode 'scope=https://prometheus.monitor.azure.com/.default' | jq -r '.access_token')
export WORKLOAD=crd-scale

ES_SERVER=https://admin:testpassword@search-perfscale-proxkqmn7am.us-west-2.es.amazonaws.com:443 WORKLOAD=${WORKLOAD} ./run.sh 
```
