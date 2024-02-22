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