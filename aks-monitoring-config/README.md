# AMA monitoring config

## AMA configuration
* Configure AKS monitoring from the Azure portal 
* Apply the configmap - `ama-metrics-settings-configmap.yaml`

# AKS Prometheus operator deployment 

## Install operator 
* Clone https://github.com/prometheus-operator/kube-prometheus.git
* Install Kube-prometheus-stack following this https://github.com/prometheus-operator/kube-prometheus?tab=readme-ov-file#quickstart
* Make sure they are up and running

## Configure to scrape from servicemonitors
* By default Prometheus will scrape metrics from `default`, `kube-system`, `monitoring` namespaces
* In order to include additional servicemonitors, it needs privileges to access them
* Create `prometheus-roleSpecificNamespaces.yaml` and `prometheus-roleBindingSpecificNamespaces.yaml` - example include `hypershift` and `cluster-aks-hosted-cp` namespaces only
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
