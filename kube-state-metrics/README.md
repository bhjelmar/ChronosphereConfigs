# kube-state-metrics

Installation instructions for deploying a chronocollector to collect metrics from kube-state-metrics.

## Overview

You can use ServiceMonitors to scrape kube-state-metrics, which generate metrics that track the health of deployments, nodes, and pods in a Kubernetes cluster. 
Monitoring these metrics can help to ensure the health of your cluster because the Collector expects to continually receive kube-state-metrics. 
If the Collector can't scrape these metrics, it's likely your Kubernetes cluster is experiencing issues you need to resolve.

Chronosphere recommends running a Collector as a Deployment or a sidecar when scraping kube-state-metrics. 
Running a Collector as a DaemonSet for this purpose is manageable for smaller clusters, but can lead to out of memory (OOM) errors as the cluster scales. 
The following steps assume that you're running the Collector as a Deployment.

[Link to documentation](https://docs.chronosphere.io/v3/documentation/admin/collector/service-discovery#kube-state-metrics-discovery) for more info

## Steps

1. deploy kube-state-metrics in the cluster
   - recommend installing via helm with either 
     - [kube-state-metrics](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-state-metrics)
       - the kube-state-metrics helm chart doesn't come with a ServiceMonitor, see [ksm-servicemonitor.yaml](manifests/ksm-servicemonitor.yaml) for an example
     - [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack)
3. install chronocollector
    - see [ksm-chronocollector-deployment.yaml](manifests/ksm-chronocollector-deployment.yaml) for an example
    - make sure to update ADDRESS and API_TOKEN
      - ADDRESS: `echo -n "MY_COMPANY.chronosphere.io:443" | base64`
      - API_TOKEN: The API token generated from your service account. `echo -n "TOKEN" | base64`

## Notes about chronocollector config

ServiceMonitor discovery is by default scoped to local node only. 
However, it is not a gurantee that the kube-state-metrics pod will be scheduled on the same node as the chronocollector pod.
To get around this, we enable `allowSkipPodInfo` to allow the chronocollector to scrape the kube-state-metrics pod regardless of where it is scheduled.

Enabling ServiceMonitor discovery will implicitly enable annotation discovery as well. 
This means anything annotated with `prometheus.io/scrape: "true"` will be scraped by the chronocollector.
For the use case of scraping kube-state-metrics, this is likely not desired.
By default, the config here sets the `podMatchingStrategy` to `service_monitors_only` to disable annotation discovery.

If we disable annotation discovery, we will need to manually specify prometheus discovery for the chronocollector self scrape job.
This is done by enabling prometheus discovery and creating a scrape job which targets `localhost:3030`.
Note the `relabel_config` which will convert the `instance` label (which defaults to useless "localhost:3030") to (the much more useful) `KUBERNETES_POD_NAME`.

## If installing the chronocollector as a DaemonSet in same cluster

It is typical to also install the chronocollector as a DaemonSet in the same cluster to capture application metrics. 
If you choose to do so alongside this Deployment, make sure you are not scraping the kube-state-metrics endpoint twice.
In your DaemonSet config, we can exclude it by adding the following to the serviceMonitorSelector: 

```yaml
serviceMonitor:
  serviceMonitorSelector:
    matchAll: false
    matchExpressions:
      - label: app.kubernetes.io/name
        operator: NotIn
        values:
          - kube-state-metrics
```