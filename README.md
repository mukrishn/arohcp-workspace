# Deploy Azure Kubernetes Service (AKS) with ARM Template

This repository contains an ARM template (`aks-arm-template.json`) to deploy an Azure Kubernetes Service (AKS) cluster using the Azure CLI (`az`) command-line interface.

## Prerequisites

Before you begin, ensure you have the following:

- Azure CLI installed and authenticated with appropriate permissions.
- An Azure subscription.
## Deployment Steps

1. **Login to Azure**: If you haven't already logged in to your Azure account, use the following command to login:
   ```bash
   az login
   ```
2. **Select Subscription**: If you have multiple subscriptions, select the appropriate one:
    ```bash
    az account set --subscription <subscription_id_or_name>
    ```
3. **Deploy the ARM Template**: Use the following command to deploy the ARM template
    ```bash
    az deployment group create --resource-group <resource_group_name> --template-file ./aks-arm-template.json
    ```
4. **Check if deployment went through**: Check the state of template based deployment
    ```bash
    az deployment group list -g perf-scale-harsha -o table
    az aks list -o table
    ```

## Retreive the kubeconfig

To access your newly deployed AKS, perform the following steps to download the kubeconfig
1. **Check "ProvisioningState" of your AKS Cluster**
    ```bash
    az aks list -o table
    ```
2. **Get access credentials for your AKS Cluster**
    ```bash
    az aks get-credentials --name <CLUSTER_NAME> --resource-group <RESOURCE_GROUP_NAME> --file /tmp/kubeconfig
    ```

## Executing the workload

The `./e2e-aks-run.sh` script is small wrapper to be used as entrypoint of some of its flags.
Currently, the following workloads are supported:

| Workloads |
|--------|
| [kubelet-density](https://github.com/mukrishn/arohcp-workspace/tree/main/kube-burner/kubelet-density) |
| [kubelet-density-cni](https://github.com/mukrishn/arohcp-workspace/tree/main/kube-burner/kubelet-density-cni) |
| [cluster-density-k8s](https://github.com/mukrishn/arohcp-workspace/tree/main/kube-burner/cluster-density-k8s) |
| [hcp-density-aks](https://github.com/mukrishn/arohcp-workspace/tree/main/kube-burner/hcp-density-aks) |

### Environment variables
This wrapper supports some variables to tweak some basic parameters, like:
- **AKS_MC_CLUSTER_NAME**: Defines the name of your AKS Cluster, by default empty.
- **ES_SERVER**: Defines the ElasticSearch/OpenSearch endpoint. By default it points the development instance. Indexing can be disabled with `export ES_SERVER=""`
- **PROM_URL**: Defines the Azure's Managed Prometheus endpoint URL for scrapping the index, by default empty.
- **TOKEN**: Defines the token corresponding to Azure's Managed Prometheus Token, by default empty.
- **WORKLOAD**: Defines the WORKLOAD, by default `kubelet-density`