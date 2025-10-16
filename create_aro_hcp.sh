set -e

export SUBSCRIPTION=${SUBSCRIPTION:-56-9d64f0c4c78f1de7e54619-1ebc2-491-}
export CLUSTER_NAME=${CLUSTER_NAME:-ps-mukri-30}
export CUSTOMER_RG_NAME="${CLUSTER_NAME}-rg"
export LOCATION=${LOCATION:-uksouth}
export CUSTOMER_NSG="${CLUSTER_NAME}-nsg"
export CUSTOMER_VNET_NAME="${CLUSTER_NAME}-vnet"
export CUSTOMER_VNET_SUBNET1="${CLUSTER_NAME}-sub"
export EXTERNAL_AUTH_NAME=${CLUSTER_NAME}-auth
export TENANT_ID=$(az account show --query tenantId --output tsv)
export ISSUER_URL="https://login.microsoftonline.com/${TENANT_ID}/v2.0"
export MANAGED_RESOURCE_GROUP="${CUSTOMER_RG_NAME}-managed"
export ACTION=${ACTION:-delete}
export MINREPLICA=${MINREPLICA:-3}
export MAXREPLICA=${MAXREPLICA:-3}
export REPLICA=${REPLICA:-3}
export TICKETID=${TICKETID:-650}
export AUTOSCALE=${AUTOSCALE:-false}

if [[ $ACTION == "create" ]]; then
	az group create --name "${CUSTOMER_RG_NAME}" --subscription "${SUBSCRIPTION}" --location "${LOCATION}" --tags TicketId=${TICKETID}
	
	echo "Create Deployment Infra..."
	az deployment group create --name 'infra' --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --template-file ~/ARO-HCP/demo/bicep/customer-infra.bicep --parameters customerNsgName="${CUSTOMER_NSG}"   customerVnetName="${CUSTOMER_VNET_NAME}" customerVnetSubnetName="${CUSTOMER_VNET_SUBNET1}"
	
	export KEYVAULT_NAME=$(az deployment group show --name 'infra' --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --query "properties.outputs.keyVaultName.value" -o tsv)
	echo "Create Deployment aro-hcp"
	az deployment group create --name 'aro-hcp' --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --template-file ~/ARO-HCP/demo/bicep/cluster.bicep --parameters vnetName="${CUSTOMER_VNET_NAME}" subnetName="${CUSTOMER_VNET_SUBNET1}" nsgName="${CUSTOMER_NSG}" clusterName="${CLUSTER_NAME}" managedResourceGroupName="${MANAGED_RESOURCE_GROUP}" keyVaultName="${KEYVAULT_NAME}"
	
	echo "Create Deployment node-pool"

	if [[ $AUTOSCALE == "true" ]]; then	
                export NP_NAME=np-autoscale
                az deployment group create --name 'node-pool-2' --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --template-file ~/ARO-HCP/demo/bicep/nodepool2.bicep --parameters clusterName="${CLUSTER_NAME}" nodePoolName="${NP_NAME}" minReplica=${MINREPLICA} maxReplica=${MAXREPLICA}
	else		
		export NP_NAME=np-static
		az deployment group create --name 'node-pool' --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --template-file ~/ARO-HCP/demo/bicep/nodepool.bicep --parameters clusterName="${CLUSTER_NAME}" nodePoolName="${NP_NAME}" replica=${REPLICA}
	fi

	echo "Create Deployment Infra pool"
	export NP_NAME=np-infra
	az deployment group create --name 'node-pool-3' --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --template-file ~/ARO-HCP/demo/bicep/nodepool-infra.bicep --parameters clusterName="${CLUSTER_NAME}" nodePoolName="${NP_NAME}"
	
	export OAUTH_CALLBACK_URL=$(az rest --method GET --uri "/subscriptions/${SUBSCRIPTION}/resourceGroups/${CUSTOMER_RG_NAME}/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters/${CLUSTER_NAME}?api-version=2024-06-10-preview" | jq -r '.properties.console.url')/auth/callback
	echo ${OAUTH_CALLBACK_URL}
	
	echo "Create AD App"
	export CLIENT_ID=$(az ad app create --display-name ${EXTERNAL_AUTH_NAME} --web-redirect-uris ${OAUTH_CALLBACK_URL} http://localhost:8000 --query appId --output tsv)
	
	echo "Create AD App Secret"
	export CLIENT_SECRET=$(az ad app credential reset --id ${CLIENT_ID} --query password --output tsv)
	export API_URL=$(az rest --method GET --uri "/subscriptions/${SUBSCRIPTION}/resourceGroups/${CUSTOMER_RG_NAME}/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters/${CLUSTER_NAME}?api-version=2024-06-10-preview" | jq -r '.properties.api.url')
	echo API_URL: $API_URL
	
	echo "Create Auth"
	az deployment group create --name 'aro-hcp-auth' --subscription "${SUBSCRIPTION}"  --resource-group "${CUSTOMER_RG_NAME}" --template-file ~/ARO-HCP/demo/bicep/externalauth.bicep --parameters externalAuthName="${EXTERNAL_AUTH_NAME}" issuerURL="${ISSUER_URL}" clientID="${CLIENT_ID}" clusterName="${CLUSTER_NAME}"
	
	echo "Pause for a 5 minute.."
	sleep 300
	
	echo "Download kubeconfig"
	echo "Get the resourceId of the ARO-HCP"
	export RESOURCE_ID=$(az resource list --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --resource-type "Microsoft.RedHatOpenShift/hcpOpenShiftClusters" | jq -r '.[].id')
	
	# Use that resourceId in following command
	# Ensure to run this commands with --debug
	echo "Create Admin Credential"
	az rest --method POST --debug --uri "${RESOURCE_ID}/requestadmincredential?api-version=2024-06-10-preview" > response.json 2> /tmp/debug-${CLUSTER_NAME}.log 
	
	export KUBECONFIG_URL=$(cat /tmp/debug-${CLUSTER_NAME}.log | grep 'Location' | awk '{print$4}' | tr -d "\"'")
	# From the response header of previous output, capture the Location value and use it in the following command
	echo $KUBECONFIG_URL

	echo SECRET: $CLIENT_SECRET

        sleep 60 	

	echo "Download Kubeconfig"
	export CMD=$(az rest --method GET --uri "${KUBECONFIG_URL}" | jq -r '.kubeconfig' > /tmp/aro-hcp-kubeconfig-${CLUSTER_NAME})
	
	oc get nodes --kubeconfig /tmp/aro-hcp-kubeconfig-${CLUSTER_NAME}

	oc create secret generic ${EXTERNAL_AUTH_NAME}-console-openshift-console --namespace openshift-config --from-literal=clientSecret=${CLIENT_SECRET} --kubeconfig /tmp/aro-hcp-kubeconfig-${CLUSTER_NAME}
	
	export GROUP_ID=$(az ad group show --group "aro-hcp-perfscale" --query id -o tsv)
	
	envsubst < ~/ARO-HCP/demo/bicep/rbac.yaml | oc --kubeconfig /tmp/aro-hcp-kubeconfig-${CLUSTER_NAME} apply -f - 

else 
	echo "Delete cluster"
        az resource delete --subscription "${SUBSCRIPTION}" --resource-group "${CUSTOMER_RG_NAME}" --name "${CLUSTER_NAME}" --resource-type "Microsoft.RedHatOpenShift/hcpOpenShiftClusters"

fi
