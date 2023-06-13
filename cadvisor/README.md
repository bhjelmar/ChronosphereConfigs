# cadvisor

Installation instructions for deploying a chronocollector to collect metrics from cadvisor.

## Overview

If running in Kubernetes, you can configure the Collector to scrape kubelet or cAdvisor metrics by setting the kubeletMetricsEnabled or cadvisorMetricsEnabled flag to true under the kubeletMonitoring YAML collection.

[Link to documentation](https://docs.chronosphere.io/v3/documentation/admin/collector/kubelet-cadvisor-metrics) for more info

## Steps

1. deploy cadvisor in the cluster
   - instructions [here](https://github.com/google/cadvisor/tree/master/deploy/kubernetes)
- install chronocollector as a DaemonSet
  - see [cadvisor-chronocollector-daemonset.yaml](manifests/cadvisor-chronocollector-daemonset.yaml) for an example
  - make sure to update ADDRESS and API_TOKEN
      - ADDRESS: `echo -n "MY_COMPANY.chronosphere.io:443" | base64`
      - API_TOKEN: The API token generated from your service account. `echo -n "TOKEN" | base64`

## Notes about chronocollector config

Since cadvisor runs as a DaemonSet, we deploy the chronocollector as a DaemonSet as well.

To monitor kubelet and cadvisor, we need to enable `kubernetes` discovery. Doing so will implicitly enable annotation discovery. 
We actually don't want annotation based discovery on by default, so we set `podMatchingStrategy` to `service_monitors_only` to disable it.
This will essentially scrape nothing by default, so we need to manually specify prometheus discovery for the chronocollector self scrape job.
If we did left annotation discovery on, we would end up double scraping the chronocollector, which we don't want.

Monitoring cadvisor requires no ServiceMonitor configuration, since `kubeletMetricsEnabled`, `cadvisorMetricsEnabled`, and `probesMetricsEnabled` does the heavy lifting automatically.