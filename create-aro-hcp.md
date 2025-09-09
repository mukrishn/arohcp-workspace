# Login your Azure account using az CLI
```
az login
```

# Clone bicep templates from upstream repo
```
git clone https://github.com/Azure/ARO-HCP.git ~/ARO-HCP/
```

# ENV vars
```
export SUBSCRIPTION=${SUBSCRIPTION:-64f0619f-ebc2-4156-9d91-c4c781de7e54}
export CLUSTER_NAME="mukrishn"
export CUSTOMER_RG_NAME="${CLUSTER_NAME}-rg"
export LOCATION="uksouth"
export CUSTOMER_NSG="${CLUSTER_NAME}-nsg"
export CUSTOMER_VNET_NAME="${CLUSTER_NAME}-vnet"
export CUSTOMER_VNET_SUBNET1="${CLUSTER_NAME}-sub"
export EXTERNAL_AUTH_NAME=${CLUSTER_NAME}-auth
export TENANT_ID=$(az account show --query tenantId --output tsv)
export ISSUER_URL="https://login.microsoftonline.com/${TENANT_ID}/v2.0"
export MANAGED_RESOURCE_GROUP="${CUSTOMER_RG_NAME}-rg-managed"
```

# CREATE CLUSTER
```
az group create --name "${CUSTOMER_RG_NAME}" --subscription "${SUBSCRIPTION}" --location "${LOCATION}"
az deployment group create --name 'infra' --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --template-file ~/ARO-HCP/demo/bicep/customer-infra.bicep --parameters customerNsgName="${CUSTOMER_NSG}"   customerVnetName="${CUSTOMER_VNET_NAME}" customerVnetSubnetName="${CUSTOMER_VNET_SUBNET1}"
export KEYVAULT_NAME=$(az deployment group show --name 'infra' --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --query "properties.outputs.keyVaultName.value" -o tsv)
az deployment group create --name 'aro-hcp' --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --template-file ~/ARO-HCP/demo/bicep/cluster.bicep --parameters vnetName="${CUSTOMER_VNET_NAME}" subnetName="${CUSTOMER_VNET_SUBNET1}" nsgName="${CUSTOMER_NSG}" clusterName="${CLUSTER_NAME}" managedResourceGroupName="${MANAGED_RESOURCE_GROUP}" keyVaultName="${KEYVAULT_NAME}"
```

# CREATE NODEPOOLS
```
export NP_NAME=np-1
az deployment group create --name 'node-pool' --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --template-file ~/ARO-HCP/demo/bicep/nodepool.bicep --parameters clusterName="${CLUSTER_NAME}" nodePoolName="${NP_NAME}" 
```

# Set External Auth - [Optional]
```
export OAUTH_CALLBACK_URL=$(az rest --method GET --uri "/subscriptions/${SUBSCRIPTION}/resourceGroups/${CUSTOMER_RG_NAME}/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters/${CLUSTER_NAME}?api-version=2024-06-10-preview" | jq -r '.properties.console.url')/auth/callback
export CLIENT_ID=$(az ad app create --display-name ${EXTERNAL_AUTH_NAME} --web-redirect-uris ${OAUTH_CALLBACK_URL} http://localhost:8000 --query appId --output tsv)
export CLIENT_SECRET=$(az ad app credential reset --id ${CLIENT_ID} --query password --output tsv)
# This secret is required at the later stage, so print it
echo $CLIENT_SECRET
export API_URL=$(az rest --method GET --uri "/subscriptions/${SUBSCRIPTION}/resourceGroups/${CUSTOMER_RG_NAME}/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters/${CLUSTER_NAME}?api-version=2024-06-10-preview" | jq -r '.properties.api.url')
az deployment group create --name 'aro-hcp-auth' --subscription "${SUBSCRIPTION}"  --resource-group "${CUSTOMER_RG_NAME}" --template-file ~/ARO-HCP/demo/bicep/externalauth.bicep --parameters externalAuthName="${EXTERNAL_AUTH_NAME}" issuerURL="${ISSUER_URL}" clientID="${CLIENT_ID}" clusterName="${CLUSTER_NAME}"
```

# Download kubeconfig
Get the resourceId of the ARO-HCP
```
az resource list --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --resource-type "Microsoft.RedHatOpenShift/hcpOpenShiftClusters" | jq '.[].id'

# Use that resourceId in following command
# Ensure to run this commands with --debug
az rest --method POST --debug --uri "<RESOURCE_ID>/requestadmincredential?api-version=2024-06-10-preview"

# From the response header of previous output, capture the Location value and use it in the following command
az rest --method GET --uri "<Location>" | jq -r '.kubeconfig' > aro-hcp-kubeconfig

oc create secret generic ${EXTERNAL_AUTH_NAME}-console-openshift-console --namespace openshift-config --from-literal=clientSecret=${CLIENT_SECRET}
export GROUP_ID=$(az ad group show --group "aro-hcp-perfscale" --query id -o tsv)
```

```yaml
oc apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: aro-admins
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: ${GROUP_ID}
EOF
```

# DELETE
```
az resource delete --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --name "${CLUSTER_NAME}" --resource-type "Microsoft.RedHatOpenShift/hcpOpenShiftClusters"
```
