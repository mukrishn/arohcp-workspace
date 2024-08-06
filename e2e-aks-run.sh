set -x
export KUBECONFIG=${KUBECONFIG:-}
export AKS_MC_CLUSTER_NAME=${AKS_MC_CLUSTER_NAME:-}
export METRIC_PROFILE=$(pwd)/kube-burner/metric-profile.yaml
export UUID="${UUID:-$(uuidgen | tr '[:upper:]' '[:lower:]')}"
export ES_SERVER=${ES_SERVER:-https://search-perfscale-dev-chmf5l4sh66lvxbnadi4bznl3a.us-west-2.es.amazonaws.com:443}
export ES_INDEX=${ES_INDEX:-}
export PROM_URL=${PROM_URL:-}
export TOKEN=${TOKEN:-}
export WORKLOAD=${WORKLOAD:-kubelet-density}

if [[ $WORKLOAD == "kubelet-density-cni" || $WORKLOAD == "kubelet-density" || $WORKLOAD == "cluster-density-k8s" || $WORKLOAD == "hcp-density-aks" ]]; then
    pushd $PWD/kube-burner/$WORKLOAD
    # export START_TIME=$(date +"%s")
    kube-burner init --config $WORKLOAD.yaml --prometheus-url="$PROM_URL" --token "$TOKEN" --metrics-profile "$METRIC_PROFILE" --skip-tls-verify
    # export END_TIME=$(date +"%s")
    # kube-burner index --uuid=${UUID} --prometheus-url=${PROM_URL} --token ${TOKEN} --start=$START_TIME --end=$END_TIME --metrics-profile ${METRIC_PROFILE} --skip-tls-verify --es-server=${ES_SERVER} --es-index=${ES_INDEX}
    kubectl delete ns -l kube-burner-job=${WORKLOAD}
    popd
else
    echo "$WORKLOAD: Choose a valid workload"
fi