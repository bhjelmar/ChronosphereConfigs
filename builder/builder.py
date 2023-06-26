import base64
import os
import re
import shutil
import subprocess
from pathlib import Path

import requests
import streamlit as st
from collections import defaultdict

import yaml
from loguru import logger
from yaml.resolver import BaseResolver


def base64Encode(s: str, encoding="ISO-8859-1"):
    strBytes = bytes(s, encoding=encoding)
    encodedBytes = base64.standard_b64encode(strBytes)
    return str(encodedBytes)[2:-1]


def main():
    st.title("Chronosphere Config Builder")
    st.markdown("---")

    recursivedict = lambda: defaultdict(recursivedict)
    config_options = recursivedict()

    general_tab, advanced_tab, scrape_tab, sink_tab, finish_tab = st.tabs(
        ["General", "Advanced", "Scrape", "Push", "Finish"])

    get_global_config(config_options, general_tab, advanced_tab)

    if config_options["deployment_type"] == "":
        return

    if config_options["global"]["in_cluster"]:
        get_kubernetes_config(config_options, scrape_tab)
    else:
        get_standalone_config(config_options, scrape_tab)

    get_ingestion_config(config_options, sink_tab)

    finalize(config_options, finish_tab)


def get_global_config(config_options, general_tab, advanced_tab):
    with general_tab:
        st.markdown("## General Config Options")

        show_help_deployment_mode = st.expander("Help", expanded=False)
        with show_help_deployment_mode:
            st.write(
                "The collector can be deployed in a few different ways. The most common is as a Kubernetes DaemonSet. The collector can also be deployed as a Kubernetes Deployment, or as a standalone binary.")
            st.markdown(
                "$\\underline{DaemonSet}$: the most common deployment mode as they ensure that the collector is deployed to every node in the cluster. Typical use cases include monitoring `cadvisor` and `node_exporter`, as well as most applications which expose Prometheus scrape endpoints.")
            st.markdown(
                "$\\underline{Deployment}$: less common, but is useful when scraping single instance applications which expose a large number of metrics. Examples include monitoring `kube-state-metrics` or a single large instance of the `OpenTelemetry Collector`.")
            st.markdown(
                "$\\underline{Standalone Binary}$: the least common deployment mode. It is useful when monitoring Prometheus endpoints which are not running in a Kubernetes environment.")

        config_options["deployment_type"] = st.radio("Select Deployment Mode",
                                                     ["",  # hidden
                                                      "Kubernetes DaemonSet",
                                                      "Kubernetes Deployment",
                                                      "Standalone Binary"
                                                      ],
                                                     horizontal=True
                                                     )

        if config_options["deployment_type"] == "Kubernetes DaemonSet":
            config_options["deployment_type"] = "daemonset"
        elif config_options["deployment_type"] == "Kubernetes Deployment":
            st.info(
                "The default behavior of the chronocollector when running as a Deployment and using Service Monitor based discovery is to scrape all pods in the cluster via allowSkipPodInfo. Make sure when running multiple collector instances that there are no shared scrape targets.")
            config_options["deployment_type"] = "deployment"
        elif config_options["deployment_type"] == "Standalone Binary":
            config_options["deployment_type"] = "standalone"
        else:
            return

        in_cluster = False if config_options["deployment_type"] == "standalone" else True
        config_options["global"]["in_cluster"] = in_cluster

        global_col1, global_col2 = st.columns(2)
        config_options["global"]["tenant"] = global_col1.text_input("Tenant", placeholder="acme")
        config_options["global"]["api_token"] = global_col2.text_input("API Token", value="", type="password")

        config_options["block_submit"] = False

        global_col1, global_col2 = st.columns(2)
        # if tenant doesn't end with chronosphere.io:443
        if config_options["global"]["tenant"] and not config_options["global"]["tenant"].endswith(
                "chronosphere.io:443"):
            first_part = config_options["global"]["tenant"].split(".")[0]
            config_options["global"]["tenant"] = f"{first_part}.chronosphere.io:443"

        connected_to_tenant = False
        # telnet to tenant to check if it's valid
        if config_options["global"]["tenant"]:
            tenant = config_options["global"]["tenant"]
            with st.spinner(f"Checking if {tenant} is a valid tenant"):
                try:
                    requests.get(f"https://{tenant}", timeout=1)
                    global_col1.success(f"Successfully connected to {tenant}")
                    connected_to_tenant = True
                except Exception:
                    global_col1.error(f"Unable to connect to {tenant}")
                    config_options["block_submit"] = True
        else:
            config_options["global"]["tenant"] = "<tenant>"

        # if token is not 64 chars
        if config_options["global"]["api_token"]:
            if len(config_options["global"]["api_token"]) != 64:
                global_col2.error("API Token appears to be malformed")
                config_options["block_submit"] = True
            else:
                if connected_to_tenant:
                    with st.spinner("Checking if API Token is valid"):
                        try:
                            auth = {"Authorization": f"Bearer {config_options['global']['api_token']}"}
                            response = requests.get(f"https://{tenant}/api/v1/config/monitors", headers=auth, timeout=1)
                            if response.ok:
                                global_col2.success("Authentication successful")
                            else:
                                global_col2.error("Authentication failed")
                                config_options["block_submit"] = True
                        except Exception:
                            global_col2.error("Authentication failed")
                            config_options["block_submit"] = True
        else:
            config_options["global"]["api_token"] = "<api_token>"

        if not config_options["global"]["tenant"] or not config_options["global"]["api_token"]:
            config_options["block_submit"] = True

        global_col1, global_col2 = st.columns(2)
        config_options["global"]["collector_name"] = global_col1.text_input(
            "Collector Name (must be unique per cluster!)",
            value=f"chronocollector-{config_options['deployment_type']}")
        config_options["global"]["collector_namespace"] = global_col2.text_input("Collector Namespace",
                                                                                 value="chronosphere")

        global_col1, global_col2 = st.columns(2)
        config_options["global"]["scrape_interval"] = global_col1.text_input("Default Scrape Interval", value="60s")
        config_options["global"]["scrape_timeout"] = global_col2.text_input("Default Scrape Timeout", value="60s")

        collector_name_regex = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
        if not re.match(collector_name_regex, config_options["global"]["collector_name"]):
            st.error(
                "Collector Name must be lowercase alphanumeric characters or '-', and must start and end with an alphanumeric character")
            config_options["block_submit"] = True

        if config_options["deployment_type"] == "daemonset" or config_options["deployment_type"] == "deployment":
            response = requests.get("https://gcr.io/v2/chronosphereio/chronocollector/tags/list")
            if not response.ok:
                st.error("Unable to fetch latest chronocollector version from GCR. Defaulting to v0.101.0")
                available_versions = ["v0.101.0"]
            else:
                manifests = response.json()["manifest"]
                sorted_by_time = sorted(manifests.items(), key=lambda x: x[1]["timeUploadedMs"], reverse=True)
                filter_by_tag = [manifest for manifest in sorted_by_time if manifest[1]["tag"]]
                available_versions = []
                for manifest in filter_by_tag:
                    version = manifest[1]["tag"][0]
                    if version.startswith("v"):
                        available_versions.append(version)
            global_col1, global_col2 = st.columns(2)
            show_release_candidates = global_col1.selectbox("Show Release Candidate Versions", [True, False], index=1)
            if not show_release_candidates:
                available_versions = [version for version in available_versions if "release-candidate" not in version]
            config_options["global"]["chronocollector_image_version"] = global_col2.selectbox("Chronocollector Version",
                                                                                              available_versions,
                                                                                              help="[Release Notes](https://docs.chronosphere.io/v3/documentation/admin/release-notes/collector)foo/configgen")

    with advanced_tab:
        st.markdown("## Advanced Config Options")
        advanced_col1, advanced_col2 = st.columns(2)
        if config_options["global"]["in_cluster"]:
            config_options["global"]["limit_cpu"] = advanced_col1.text_input("Limit CPU", value="1000m")
            config_options["global"]["limit_memory"] = advanced_col2.text_input("Limit Memory", value="512Mi")
            config_options["global"]["request_cpu"] = advanced_col1.text_input("Request CPU", value="1000m")
            config_options["global"]["request_memory"] = advanced_col2.text_input("Request Memory", value="512Mi")
        advanced_col1, advanced_col2 = st.columns(2)
        config_options["global"]["logging_level"] = advanced_col1.selectbox("Logging Level",
                                                                            ["info", "debug", "warn", "error", "fatal",
                                                                             "panic"])
        config_options["global"]["compression_format"] = advanced_col2.selectbox("Compression Format",
                                                                                 ["zstd", "snappy"],
                                                                                 help="The zstd algorithm can greatly reduce network egress cost, which can reduce the data flowing out of your network by up to 60% compared to snappy. On average, zstd requires about 15% more memory than snappy, but offers a compression ration that's 2.5 times greater.")

        st.markdown("---")
        advanced_col1, advanced_col2 = st.columns(2)
        config_options["global"]["ingestion_buffering"] = advanced_col1.selectbox("Ingestion Buffering", ["off", "on"],
                                                                                  help="The collector can retry a subset of metric upload failures (explicitly excludes rate-limited uploads and malformed metrics).")
        ingestion_buffering_disabled = False if config_options["global"]["ingestion_buffering"] == "on" else True
        config_options["global"]["ingestion_buffering_directory"] = advanced_col2.text_input(
            "Ingestion Buffer Directory",
            placeholder="/tmp/chronocollector-buffer",
            disabled=ingestion_buffering_disabled)
        config_options["global"]["ingestion_buffering_ttl"] = advanced_col1.slider("Ingestion Buffer TTL (seconds)",
                                                                                   min_value=1, max_value=90, value=90,
                                                                                   disabled=ingestion_buffering_disabled)
        config_options["global"]["ingestion_buffering_max_size"] = advanced_col2.slider("Ingestion Buffer Size (mb)",
                                                                                        min_value=1, max_value=100,
                                                                                        value=10,
                                                                                        help="The ingestion buffer size is the number of metric batches that can be buffered in memory before the collector starts dropping metrics. The collector will drop the oldest batch of metrics when the buffer is full.",
                                                                                        disabled=ingestion_buffering_disabled)

        st.markdown("---")
        advanced_col1, advanced_col2 = st.columns(2)
        config_options["global"]["connection_pooling"] = advanced_col1.selectbox("Connection Pooling", ["off", "on"],
                                                                                 help="A single Collector instance is capable of high throughput. However, if the Collector sends metrics at more than 100 requests per second, enable connection pooling to improve overall throughput in the client. If you enable self-scraping, you can submit the following query with Metrics Explorer to verify the connection pooling setting: sum by(instance) (rate(chronocollector_gateway_push_latency_count[1m])) > 100")
        connection_pooling_disabled = False if config_options["global"]["connection_pooling"] == "on" else True
        config_options["global"]["connection_pool_size"] = advanced_col2.slider("Connection Pool Size",
                                                                                min_value=1, max_value=8, value=4,
                                                                                disabled=connection_pooling_disabled)

        st.markdown("---")
        advanced_col1, advanced_col2 = st.columns(2)
        config_options["global"]["staleness_markers"] = advanced_col1.selectbox("Staleness Markers", ["off", "on"],
                                                                                help="When a scrape target disappears or doesn't return a sample for a time series that was present in a previous scrape, queries return the last value. After five minutes, queries return no value, which means queries might return out-of-date data.By enabling staleness markers, the Collector can hint to the database that a time series has gone stale, and exclude it from query results until it reappears. A staleness marker gets published when the target disappears or doesn't return a sample. Staleness markers disabled by default in the Collector configuration."
                                                                                )


def get_kubernetes_config(config_options: dict, scrape_tab):
    config_options["global"]["labels"] = [] if "global_labels" not in st.session_state else st.session_state[
        "global_labels"]

    with scrape_tab:
        st.markdown("## Scape Configuration")
        with st.form("global_labels_form", clear_on_submit=True):
            st.markdown("### Add Global Metric Labels",
                        help="Global labels are applied to all metrics collected by the collector.")
            global_col1_key, global_col2_value, global_col3_button = st.columns(3)

            new_key = global_col1_key.text_input("Match Label", key="new_global_label_key",
                                                 placeholder="environment" if not config_options["global"][
                                                     "labels"] else "")
            new_value = global_col2_value.text_input("Match Value", key="new_global_label_value",
                                                     placeholder="prod" if not config_options["global"][
                                                         "labels"] else "")
            global_col3_button.write("##")
            if global_col3_button.form_submit_button("Add"):
                if any(label["key"] == new_key for label in config_options["global"]["labels"]):
                    st.error(f"Label key already exists")
                elif not new_key:
                    st.error(f"Label key cannot be empty")
                elif not re.match(r"^[a-zA-Z_]([a-zA-Z0-9_])*$", new_key):
                    st.error(
                        f"Label key must start with a letter or an underscore, followed by any combination of letters, numbers, or underscores.")
                else:
                    if not "global_labels" in st.session_state:
                        st.session_state["global_labels"] = []
                    st.session_state["global_labels"].append({"key": new_key, "value": new_value})
                    st.experimental_rerun()

        if "global_labels" in st.session_state and len(st.session_state["global_labels"]):
            st.write("### Global Labels")
            for label in config_options["global"]["labels"]:
                global_col1_key, global_col2_value, global_col3_button = st.columns(3)
                global_col1_key.text(label["key"])
                global_col2_value.text(label["value"])
                if global_col3_button.button("Remove", key=label["key"]):
                    config_options["global"]["labels"].remove(label)
                    st.session_state["global_labels"] = config_options["global"]["labels"]
                    st.experimental_rerun()

        st.markdown("---")
        st.markdown("### Common Discovery Targets")
        common_col1, common_col2, common_col3, common_col4 = st.columns(4)

        if config_options["deployment_type"] == "daemonset":
            config_options["monitor_cadvisor"] = common_col1.checkbox("cadvisor",
                                                                      help="cAdvisor (Container Advisor) provides container users an understanding of the resource usage and performance characteristics of their running containers. It is a running daemon that collects, aggregates, processes, and exports information about running containers. Specifically, for each container it keeps resource isolation parameters, historical resource usage, histograms of complete historical resource usage and network statistics. This data is exported by container and machine-wide.")
            config_options["monitor_kubelet"] = common_col2.checkbox("kubelet")
            config_options["monitor_probes"] = common_col3.checkbox("probes")
            config_options["monitor_kube_system"] = common_col4.checkbox("kube-system",
                                                                         help="Discover endpoints in the kube-system namespace. Because kube-system has many constantly changing endpoints that may cause unnecessary load on the Collector, the endpoint is disabled by default.")
            config_options["enable_collector_metrics"] = common_col1.checkbox("Chronocollector Self Scrape", value=True)
        elif config_options["deployment_type"] == "deployment":
            # config_options["monitor_ksm"] = common_col1.checkbox("kube-state-metrics")
            config_options["enable_collector_metrics"] = common_col1.checkbox("Chronocollector Self Scrape", value=True)
            config_options["monitor_kubelet"] = False
            config_options["monitor_probes"] = False
            config_options["monitor_kube_system"] = False
        else:
            config_options["enable_collector_metrics"] = common_col1.checkbox("Chronocollector Self Scrape", value=True)
            config_options["monitor_kubelet"] = False
            config_options["monitor_probes"] = False
            config_options["monitor_kube_system"] = False

        if not config_options["enable_collector_metrics"]:
            st.write("---")
            st.warning(
                "It is not recommended to disable the Chronocollector self scrape. Disabling this will prevent the collector from collecting metrics about itself.")

        # if config_options["monitor_ksm"]:
        #     st.markdown("---")
        #     st.markdown(
        #         "kube-state-metrics Selected in Deployment type configuration. Ensure KSM is not [sharded](https://github.com/kubernetes/kube-state-metrics#daemonset-sharding-for-pod-metrics). If it is, please select the Daemonset deployment type.")

        st.markdown("---")
        st.markdown("### Discovery Config Options")

        show_help_discovery_config = st.expander("Show Discovery Config Help")
        with show_help_discovery_config:
            st.markdown(
                "$\\underline{Service Monitor Discovery}$: Discover targets using Service Monitors. This CRD comes with [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator), and is the recommended way to discover targets. The chronocollector will discover Service Monitors with the labeled with `'<match_label>': '<match_value>'` as configured below.")
            st.markdown(
                "$\\underline{Annotation Discovery}$: Discover targets using annotations on pods. The chronocollector will discover pods with the annotation `prometheus.io/scrape: 'true'` and `prometheus.io/port: '<port>'` where `<port>` is the port to scrape on the pod. The default annotation prefix is `prometheus.io/` but can be changed below.")
            st.markdown(
                "$\\underline{Prometheus Discovery}$: Discover targets using Prometheus Jobs. This is the legacy way to discover targets, and is not typically recommended as it is more challenging to set up than the other methods. While other methods of service discovery exist, this tool only provides an UI to create static Prometheus Jobs. See documentation [here](https://prometheus.io/docs/prometheus/latest/configuration/configuration) for more additional configuration types.")
        st.markdown("---")
        discovery_col1, discovery_col2, discovery_col3 = st.columns(3)
        config_options["use_service_monitors"] = discovery_col1.checkbox("Enable Service Monitor Discovery")
        if config_options["use_service_monitors"]:
            st.markdown("---")
            st.markdown("### Service Monitors Discovery Config")

            st.markdown(
                "Discover individual Service Monitors for discovery below or select 'Monitor All Service Monitors' to discover all Service Monitors.")
            config_options["discover_all_service_monitors"] = st.checkbox("Discover All Service Monitors", value=False)
            if not config_options["discover_all_service_monitors"]:
                config_options["service_monitors"] = [] if "service_monitors" not in st.session_state else \
                    st.session_state[
                        "service_monitors"]
                with st.form(key="service_monitor_form", clear_on_submit=True):
                    st.markdown("Add a Service Monitor")
                    servie_monitor_form_col1, service_monitor_form_col2, service_monitor_form_col3 = st.columns(3)
                    service_monitor_match_label = servie_monitor_form_col1.text_input("Service Monitor Match Label",
                                                                                      placeholder="foo",
                                                                                      key=f"service_monitor_match_label")
                    service_monitor_match_value = service_monitor_form_col2.text_input("Service Monitor Match Value",
                                                                                       placeholder="bar",
                                                                                       key=f"service_monitor_match_value")
                    service_monitor_form_col3.write("##")
                    service_monitor_submit = service_monitor_form_col3.form_submit_button("Add Service Monitor")
                    if service_monitor_submit:
                        config_options["service_monitors"].append({
                            "match_label": service_monitor_match_label,
                            "match_value": service_monitor_match_value,
                        })
                        st.session_state["service_monitors"] = config_options["service_monitors"]

                if "service_monitors" in st.session_state and len(st.session_state["service_monitors"]) > 0:
                    st.markdown("### Service Monitors")
                    for i, service_monitor in enumerate(config_options["service_monitors"]):
                        service_monitor_col1, service_monitor_col2, service_monitor_col3 = st.columns(3)
                        service_monitor_col1.text(service_monitor["match_label"])
                        service_monitor_col2.text(service_monitor["match_value"])
                        if service_monitor_col3.button("Remove", key=f"service_monitor_remove_{i}"):
                            config_options["service_monitors"].remove(service_monitor)
                            st.session_state["service_monitors"] = config_options["service_monitors"]
                            st.experimental_rerun()
            else:
                st.warning(
                    "All Service Monitors will be discovered. This may result in a large number of targets. If you are running any other chronocollector instances in this cluster, please sure there is not overlap in the Service Monitors discovered.")

        config_options["use_annotations"] = discovery_col2.checkbox("Enable Annotation Discovery")
        if config_options["use_annotations"]:
            st.markdown("---")
            st.markdown("### Annotations Discovery Config")
            annotations_col1, annotations_col2 = st.columns(2)
            config_options["annotations"]["annotation_prefix"] = annotations_col1.text_input("Annotation Prefix",
                                                                                             value="prometheus.io/")
        else:
            config_options["annotations"]["annotation_prefix"] = "prometheus.io/"

        use_prometheus = discovery_col3.checkbox("Enable Prometheus Discovery")
        if use_prometheus:
            st.markdown("---")
            st.markdown("### Prometheus Discovery Config")

            config_options["prometheus_jobs"] = [] if "prometheus_jobs" not in st.session_state else st.session_state[
                "prometheus_jobs"]
            with st.form(key="prometheus_job_form", clear_on_submit=True):
                st.markdown("Add a Prometheus Job")

                prom_col1, prom_col2, prom_col3, prom_col4, prom_col5 = st.columns(5)
                job_name = prom_col1.text_input("Job Name", key=f"job_name", placeholder="node_exporter")
                scrape_interval = prom_col2.text_input("Scrape Interval", key=f"scrape_interval",
                                                       value=config_options["global"]["scrape_interval"])
                scrape_timeout = prom_col3.text_input("Scrape Timeout", key=f"scrape_timeout",
                                                      value=config_options["global"]["scrape_timeout"])
                targets = prom_col4.text_input("Targets", key=f"targets", placeholder="localhost:9100",
                                               help="Comma separated list of targets (e.g. localhost:9090,localhost:9091)")

                prom_col5.write("##")
                prom_job_submit = prom_col5.form_submit_button("Add Prometheus Job")
                if prom_job_submit:
                    config_options["prometheus_jobs"].append({
                        "job_name": job_name,
                        "scrape_interval": scrape_interval,
                        "scrape_timeout": scrape_timeout,
                        "targets": targets
                    })
                    st.session_state["prometheus_jobs"] = config_options["prometheus_jobs"]

            if "prometheus_jobs" in st.session_state and len(st.session_state["prometheus_jobs"]) > 0:
                st.markdown("### Prometheus Jobs")
                for i, prometheus_job in enumerate(config_options["prometheus_jobs"]):
                    prom_col1, prom_col2, prom_col3, prom_col4, prom_col5 = st.columns(5)
                    prom_col1.text(prometheus_job["job_name"])
                    prom_col2.text(prometheus_job["scrape_interval"])
                    prom_col3.text(prometheus_job["scrape_timeout"])
                    prom_col4.text(prometheus_job["targets"])
                    if prom_col5.button("Remove", key=f"kubernetes_prom_job_remove_{i}"):
                        config_options["prometheus_jobs"].remove(prometheus_job)
                        st.session_state["prometheus_jobs"] = config_options["prometheus_jobs"]
                        st.experimental_rerun()


def get_standalone_config(config_options: dict, scrape_tab):
    config_options["global"]["labels"] = [] if "global_labels" not in st.session_state else st.session_state[
        "global_labels"]
    with scrape_tab:
        st.markdown("## Service Discovery Config Options")
        with st.form("global_labels_form", clear_on_submit=True):
            st.markdown("### Add Global Metric Labels",
                        help="Global labels are applied to all metrics collected by the collector.")
            global_col1_key, global_col2_value, global_col3_button = st.columns(3)

            new_key = global_col1_key.text_input("Match Label", key="new_global_label_key",
                                                 placeholder="environment" if not config_options["global"][
                                                     "labels"] else "")
            new_value = global_col2_value.text_input("Match Value", key="new_global_label_value",
                                                     placeholder="prod" if not config_options["global"][
                                                         "labels"] else "")
            global_col3_button.write("##")
            if global_col3_button.form_submit_button("Add"):
                if any(label["key"] == new_key for label in config_options["global"]["labels"]):
                    st.error(f"Label key already exists")
                elif not new_key:
                    st.error(f"Label key cannot be empty")
                elif not re.match(r"^[a-zA-Z_]([a-zA-Z0-9_])*$", new_key):
                    st.error(
                        f"Label key must start with a letter or an underscore, followed by any combination of letters, numbers, or underscores.")
                else:
                    if not "global_labels" in st.session_state:
                        st.session_state["global_labels"] = []
                    st.session_state["global_labels"].append({"key": new_key, "value": new_value})
                    st.experimental_rerun()

        if "global_labels" in st.session_state and len(st.session_state["global_labels"]):
            st.write("### Global Labels")
            for label in config_options["global"]["labels"]:
                global_col1_key, global_col2_value, global_col3_button = st.columns(3)
                global_col1_key.text(label["key"])
                global_col2_value.text(label["value"])
                if global_col3_button.button("Remove", key=label["key"]):
                    config_options["global"]["labels"].remove(label)
                    st.session_state["global_labels"] = config_options["global"]["labels"]
                    st.experimental_rerun()

        st.markdown("---")
        st.markdown("### Common Discovery Targets")
        common_col1, common_col2, common_col3, common_col4 = st.columns(4)
        config_options["enable_collector_metrics"] = common_col1.checkbox("Chronocollector Self Scrape", value=True)

        if not config_options["enable_collector_metrics"]:
            st.write("---")
            st.warning(
                "It is not recommended to disable the Chronocollector self scrape. Disabling this will prevent the collector from collecting metrics about itself.")

        st.write("---")
        st.markdown("### Discovery Config Options")
        config_options["prometheus_jobs"] = [] if "prometheus_jobs" not in st.session_state else st.session_state[
            "prometheus_jobs"]
        with st.form(key="prometheus_job_form", clear_on_submit=True):
            st.markdown("Add a Prometheus Job")

            prom_col1, prom_col2, prom_col3, prom_col4, prom_col5 = st.columns(5)
            job_name = prom_col1.text_input("Job Name", key=f"job_name", placeholder="node_exporter")
            scrape_interval = prom_col2.text_input("Scrape Interval", key=f"scrape_interval",
                                                   value=config_options["global"]["scrape_interval"])
            scrape_timeout = prom_col3.text_input("Scrape Timeout", key=f"scrape_timeout",
                                                  value=config_options["global"]["scrape_timeout"])
            targets = prom_col4.text_input("Targets", key=f"targets", placeholder="localhost:9100",
                                           help="Comma separated list of targets (e.g. localhost:9090,localhost:9091)")

            prom_col5.write("##")
            prom_job_submit = prom_col5.form_submit_button("Add Prometheus Job")
            if prom_job_submit:
                config_options["prometheus_jobs"].append({
                    "job_name": job_name,
                    "scrape_interval": scrape_interval,
                    "scrape_timeout": scrape_timeout,
                    "targets": targets
                })
                st.session_state["prometheus_jobs"] = config_options["prometheus_jobs"]

        if "prometheus_jobs" in st.session_state and len(st.session_state["prometheus_jobs"]) > 0:
            st.markdown("### Prometheus Jobs")
            for i, prometheus_job in enumerate(config_options["prometheus_jobs"]):
                prom_col1, prom_col2, prom_col3, prom_col4, prom_col5 = st.columns(5)
                prom_col1.text(prometheus_job["job_name"])
                prom_col2.text(prometheus_job["scrape_interval"])
                prom_col3.text(prometheus_job["scrape_timeout"])
                prom_col4.text(prometheus_job["targets"])
                if prom_col5.button("Remove", key=f"standalone_prom_job_remove_{i}"):
                    config_options["prometheus_jobs"].remove(prometheus_job)
                    st.session_state["prometheus_jobs"] = config_options["prometheus_jobs"]
                    st.experimental_rerun()


def get_ingestion_config(config_options, sink_tab):
    with sink_tab:
        st.markdown("## Ingestion Config Options")

        dogstatsd, graphite, openmetrics, pushgateway, traces = st.tabs(
            ["DogStatsD", "Graphite", "Prometheus/OpenMetrics", "Pushgateway", "Traces"])

        with dogstatsd:
            st.markdown("### DogStatsD")
            st.info(
                "All ingested DogStatsD metrics are subject to sanitization rules that follows Datadog's own [best practice guidelines](https://docs.datadoghq.com/developers/guide/what-best-practices-are-recommended-for-naming-metrics-and-tags/]). For example, Chronosphere converts all DogStatsD labels to lowercase.")

            config_options["dogstatsd"]["labels"] = [] if "dogstatsd_labels" not in st.session_state else \
                st.session_state[
                    "dogstatsd_labels"]
            with st.form("dogstatsd_form", clear_on_submit=True):
                st.markdown("### Add Global DogStatsd Labels",
                            help="Adds one or more labels to all DogStatsD metrics pushed.")
                dogstatsd_label_col1_key, dogstatsd_label_col2_value, dogstatsd_label_col3_button = st.columns(3)

                new_key = dogstatsd_label_col1_key.text_input("Match Label", key="dogstatsd_label_key",
                                                              placeholder="environment" if not config_options["global"][
                                                                  "labels"] else "")
                new_value = dogstatsd_label_col2_value.text_input("Match Value", key="dogstatsd_label_value",
                                                                  placeholder="prod" if not config_options["global"][
                                                                      "labels"] else "")
                dogstatsd_label_col3_button.write("##")
                if dogstatsd_label_col3_button.form_submit_button("Add"):
                    if any(label["key"] == new_key for label in config_options["dogstatsd"]["labels"]):
                        st.error(f"Label key already exists")
                    elif not new_key:
                        st.error(f"Label key cannot be empty")
                    elif not re.match(r"^[a-zA-Z_]([a-zA-Z0-9_])*$", new_key):
                        st.error(
                            f"Label key must start with a letter or an underscore, followed by any combination of letters, numbers, or underscores.")
                    else:
                        if not "dogstatsd_labels" in st.session_state:
                            st.session_state["dogstatsd_labels"] = []
                        st.session_state["dogstatsd_labels"].append({"key": new_key, "value": new_value})
                        st.experimental_rerun()

            if "dogstatsd_labels" in st.session_state and len(st.session_state["dogstatsd_labels"]):
                st.write("### Global DogStatsD Labels")
                for label in config_options["dogstatsd"]["labels"]:
                    dogstatsd_label_col1_key, dogstatsd_label_col2_value, dogstatsd_label_col3_button = st.columns(3)
                    dogstatsd_label_col1_key.text(label["key"])
                    dogstatsd_label_col2_value.text(label["value"])
                    if dogstatsd_label_col3_button.button("Remove", key=f'dogatstsd_label["key"]'):
                        config_options["dogstatsd"]["labels"].remove(label)
                        st.session_state["dogstatsd_labels"] = config_options["dogstatsd"]["labels"]
                        st.experimental_rerun()

            st.markdown("---")

            dogstatsd_col1, dogstatsd_col2 = st.columns(2)
            dogstatsd_enabled_str = dogstatsd_col1.selectbox("DogStatsD", ["off", "on"])
            config_options["dogstatsd"]["enabled"] = True if dogstatsd_enabled_str == "on" else False
            config_options["dogstatsd"]["listenAddress"] = dogstatsd_col2.text_input("Listen Address",
                                                                                     value="0.0.0.0:9125",
                                                                                     disabled=not
                                                                                     config_options["dogstatsd"][
                                                                                         "enabled"],
                                                                                     help="The address the UDP server listens on. The default is 0.0.0.0:9125. This address is what your DogStatsD client should point to.")
            dogstatsd_col1, dogstatsd_col2 = st.columns(2)
            config_options["dogstatsd"]["mode"] = dogstatsd_col1.selectbox("Mode",
                                                                           ["regular", "graphite", "graphite_expanded"],
                                                                           disabled=not config_options["dogstatsd"][
                                                                               "enabled"],
                                                                           help="""You can run DogStatsD ingestion in one of these modes when converting [DogStatsD METRIC_NAME](https://docs.datadoghq.com/developers/dogstatsd/datagram_shell/?tab=metrics) into Prometheus labels: regular, graphite, or graphite_expanded. []()

    - regular (default): DogStatsD METRIC_NAME is assigned the Prometheus __name__ label, replacing all non-alphanumeric and non-dot characters with underscores, with dots changing to underscores (_).

      For example, the METRIC_NAME my.very.first-metric changes to my_very_first_metric{}.

    - graphite: The Prometheus __name__ label receives a constant stat name and the DogStatsD METRIC_NAME assigned to a Prometheus label set in the configuration nameLabelName (default name).

      For example, the METRIC_NAME my.very.first-metric changes to stat{name="my.very.first-metric"}.

    - graphite_expanded: The same as graphite mode, except in addition to storing everything in the nameLabelName label, it splits METRIC_NAME at each . and stores each part in separate labels named like t0, t1, t2, and so on.

      For example, the METRIC_NAME my.very.first-metric changes to stat{name="my.very.first-metric", t0="my", t1="very", t2="first-metric"}.""")
            is_regular_mode = True if config_options["dogstatsd"]["mode"] == "regular" else False
            config_options["dogstatsd"]["nameLabelName"] = dogstatsd_col2.text_input("\"name\" Label Name",
                                                                                     value="name",
                                                                                     disabled=not
                                                                                              config_options[
                                                                                                  "dogstatsd"][
                                                                                                  "enabled"] or is_regular_mode,
                                                                                     help="Defines the label name used to store METRIC_NAME in the graphite and graphite_expanded modes.")
            dogstatsd_col1, dogstatsd_col2 = st.columns(2)
            config_options["dogstatsd"]["prefix"] = dogstatsd_col1.text_input("Prefix",
                                                                              disabled=not config_options["dogstatsd"][
                                                                                  "enabled"],
                                                                              help="Adds a prefix to all DogStatsD metrics pushed.")

            st.markdown("---")
            dogstatsd_col1, dogstatsd_col2 = st.columns(2)
            config_options["dogstatsd"]["aggregations"]["enabled"] = dogstatsd_col1.selectbox("Aggregations",
                                                                                              ["off", "on"],
                                                                                              help="Enables or disables aggregations for DogStatsD metrics.")
            dogstatsd_agg_disabled = False if config_options["dogstatsd"]["aggregations"]["enabled"] == "on" else True
            config_options["dogstatsd"]["aggregations"]["enabled"] = not dogstatsd_agg_disabled
            config_options["dogstatsd"]["aggregations"]["counters"]["interval"] = dogstatsd_col2.text_input(
                "Counters Interval", value="10s", help="The interval at which to aggregate counters.",
                disabled=dogstatsd_agg_disabled)

            dogstatsd_col1, dogstatsd_col2 = st.columns(2)
            config_options["dogstatsd"]["aggregations"]["gauges"]["interval"] = dogstatsd_col1.text_input(
                "Gauges Interval",
                value="10s",
                help="The interval at which to aggregate gauges.",
                disabled=dogstatsd_agg_disabled)
            config_options["dogstatsd"]["aggregations"]["timers"]["interval"] = dogstatsd_col2.text_input(
                "Timers Interval",
                value="10s",
                help="The interval at which to aggregate timers.",
                disabled=dogstatsd_agg_disabled)
            dogstatsd_col1, dogstatsd_col2 = st.columns(2)
            config_options["dogstatsd"]["aggregations"]["inactiveExpireAt"] = dogstatsd_col1.text_input(
                "Inactive Expire At", value="2m", help="The time after which to expire inactive aggregations.",
                disabled=dogstatsd_agg_disabled)

        with graphite:
            st.markdown("## Graphite")
            st.info(
                "The Collector supports graphite metrics and two different ways to set up Graphite ingestion: StatsD or Carbon. To enable or make changes to Graphite ingestion, contact your account manager to arrange for the appropriate backend changes.")
            st.markdown("### StatsD")
            st.markdown("---")

            statsd_col1, statsd_col2 = st.columns(2)
            config_options["statsd"]["enabled"] = statsd_col1.selectbox("Enabled", ["off", "on"], key="statsd_enabled",
                                                                        help="StatsD sends unaggregated data to the Collector and Chronosphere aggregation rules to ensure they get aggregated appropriately. To ingest StatsD metrics with the Collector, add the following to the configuration file under the push key:")
            config_options["statsd"]["enabled"] = True if config_options["statsd"]["enabled"] == "on" else False
            config_options["statsd"]["listenAddress"] = statsd_col2.text_input("Listen Address", value="0.0.0.0:3031",
                                                                               key="statsd_listen_address",
                                                                               disabled=not config_options["statsd"][
                                                                                   "enabled"])

            st.markdown("---")
            st.markdown("### Carbon")
            carbon_col1, carbon_col2 = st.columns(2)
            config_options["carbon"]["enabled"] = carbon_col1.selectbox("Enabled", ["off", "on"], key="carbon_enabled",
                                                                        help="""
Carbon is another approach to sending Graphite data to the Collector. With this method, Chronosphere treats any Carbon data as pre-aggregated before it arrives at the Collector. Downsampling rules apply only for long-term retention with all metrics assumed to be gauges, while the short-term retention data is persisted as-is.

Only use this when you are certain about the resolution of the data sent, with any change in resolution causing Chronosphere to persist more metrics. In general, Chronosphere doesn't recommend this approach of sending Graphite metrics, as the resolution and control of metrics ingestion is defined by the Carbon clients sending the data, and not the Collector or backend.""")
            config_options["carbon"]["enabled"] = True if config_options["carbon"]["enabled"] == "on" else False
            config_options["carbon"]["listenAddress"] = carbon_col2.text_input("Listen Address", value="0.0.0.0:2003",
                                                                               key="carbon_listen_address",
                                                                               disabled=not config_options["carbon"][
                                                                                   "enabled"])

        # Prometheus and OpenMetrics
        with openmetrics:
            st.markdown("## Prometheus and OpenMetrics")
            st.write(
                "Traffic is served from /import/openmetrics and /import/prometheus from the global collector listenAddress, which defaults to 0.0.0.0:3030.")
            st.write(
                "View [documentation](https://docs.chronosphere.io/v3/documentation/admin/collector/ingest-metrics) for more information.")

            st.markdown("---")
            st.markdown("### Prometheus")
            st.markdown("---")

            prometheus_col1, prometheus_col2 = st.columns(2)
            config_options["prometheus"]["enabled"] = prometheus_col1.selectbox("Enabled", ["off", "on"],
                                                                                key="prometheus_enabled")
            config_options["prometheus"]["enabled"] = True if config_options["prometheus"]["enabled"] == "on" else False

            st.markdown("---")
            st.markdown("### OpenMetrics")
            openmetrics_col1, openmetrics_col2 = st.columns(2)
            config_options["openmetrics"]["enabled"] = openmetrics_col1.selectbox("Enabled", ["off", "on"],
                                                                                  key="openmetrics_enabled")
            config_options["openmetrics"]["enabled"] = True if config_options["openmetrics"][
                                                                   "enabled"] == "on" else False

        # Pushgateway
        with pushgateway:
            st.markdown("### Pushgateway")

            st.write(
                "Collector provides an HTTP endpoint that's compatible with the [Prometheus Pushgateway](https://github.com/prometheus/pushgateway). Traffic is served from the global collector listenAddress, which defaults to 0.0.0.0:3030.")
            st.write(
                "View [documentation](https://docs.chronosphere.io/v3/documentation/admin/collector/ingest-metrics#pushgateway-ingestion) for more information.")

            pushgateway_col1, pushgateway_col2 = st.columns(2)
            config_options["pushgateway"]["enabled"] = pushgateway_col1.selectbox("Enabled", ["off", "on"],
                                                                                  key="pushgateway_enabled")
            config_options["pushgateway"]["enabled"] = True if config_options["pushgateway"][
                                                                   "enabled"] == "on" else False

        # Traces
        with traces:
            st.markdown("### Traces")

            if config_options["deployment_type"] == "daemonset":
                st.warning(
                    "The recommended way to install the Collector to receive trace data is with a Kubernetes Deployment. ")

            st.write(
                "For more information, view [documentation](https://docs.chronosphere.io/documentation/admin/collector/tracing).")
            st.markdown("---")

            st.markdown("### Otel")
            traces_col1, traces_col2 = st.columns(2)
            config_options["otel"]["enabled"] = traces_col1.selectbox("Enabled", ["off", "on"], key="otel_enabled")
            config_options["otel"]["enabled"] = True if config_options["otel"]["enabled"] == "on" else False
            config_options["otel"]["listenAddress"] = traces_col2.text_input("Listen Address", value="0.0.0.0:4317",
                                                                             key="otel_listen_address",
                                                                             disabled=not config_options["otel"][
                                                                                 "enabled"])
            config_options["otel"]["httpEnabled"] = traces_col1.selectbox("HTTP Enabled", ["off", "on"],
                                                                          key="otel_http_enabled",
                                                                          disabled=not config_options["otel"][
                                                                              "enabled"])
            config_options["otel"]["httpEnabled"] = True if config_options["otel"]["httpEnabled"] == "on" else False
            config_options["otel"]["httpListenAddress"] = traces_col2.text_input("HTTP Listen Address",
                                                                                 value="0.0.0.0:4318",
                                                                                 key="otel_http_listen_address",
                                                                                 disabled=not config_options["otel"][
                                                                                     "httpEnabled"])

            st.markdown("---")
            st.markdown("### Jaeger")
            traces_col1, traces_col2 = st.columns(2)
            config_options["jaeger"]["enabled"] = traces_col1.selectbox("Enabled", ["off", "on"], key="jaeger_enabled")
            config_options["jaeger"]["enabled"] = True if config_options["jaeger"]["enabled"] == "on" else False
            config_options["jaeger"]["listenAddress"] = traces_col2.text_input("Listen Address", value="0.0.0.0:6831",
                                                                               key="jaeger_listen_address",
                                                                               disabled=not config_options["jaeger"][
                                                                                   "enabled"])

            st.markdown("---")
            st.markdown("### Zipkin")
            traces_col1, traces_col2 = st.columns(2)
            config_options["zipkin"]["enabled"] = traces_col1.selectbox("Enabled", ["off", "on"], key="zipkin_enabled")
            config_options["zipkin"]["enabled"] = True if config_options["zipkin"]["enabled"] == "on" else False
            config_options["zipkin"]["listenAddress"] = traces_col2.text_input("Listen Address", value="0.0.0.0:9411",
                                                                               key="zipkin_listen_address",
                                                                               disabled=not config_options["zipkin"][
                                                                                   "enabled"])


def generate_config(config_options):
    config_output = {}

    log_level = config_options["global"]["logging_level"] if "logging_level" in config_options["global"] else "info"
    config_output["logging"] = {}
    config_output["logging"]["level"] = log_level

    config_output["metrics"] = {}
    config_output["metrics"]["scope"] = {}
    config_output["metrics"]["scope"]["prefix"] = "chronocollector"
    config_output["metrics"]["scope"]["tags"] = {}
    config_output["metrics"]["prometheus"] = {}
    config_output["metrics"]["prometheus"]["handlerPath"] = "/metrics"
    config_output["metrics"]["sanitization"] = "prometheus"
    config_output["metrics"]["samplingRate"] = 1.0
    config_output["metrics"]["extended"] = "none"

    config_output["listenAddress"] = "${LISTEN_ADDRESS:0.0.0.0:3030}"

    if len(config_options["global"]["labels"]) > 0:
        config_output["labels"] = {}
        config_output["labels"]["defaults"] = {}
        for label in config_options["global"]["labels"]:
            config_output["labels"]["defaults"][label["key"]] = label["value"]

    config_output["backend"] = {}
    config_output["backend"]["type"] = "${BACKEND_TYPE:gateway}"
    config_output["backend"]["annotatedMetrics"] = "${BACKEND_ANNOTATED_METRICS:false}"
    config_output["backend"]["gateway"] = {}
    config_output["backend"]["gateway"]["address"] = "${GATEWAY_ADDRESS:\"\"}"
    config_output["backend"]["gateway"]["serverName"] = "${GATEWAY_SERVER_NAME:\"\"}"
    config_output["backend"]["gateway"]["insecure"] = "${GATEWAY_INSECURE:false}"
    config_output["backend"]["gateway"]["cert"] = "${GATEWAY_CERT:\"\"}"
    config_output["backend"]["gateway"]["certSkipVerify"] = "${GATEWAY_CERT_SKIP_VERIFY:false}"
    config_output["backend"]["gateway"]["apiTokenFile"] = "${API_TOKEN_FILE:\"\"}"
    compression_format = config_options["global"]["compression_format"] if "compression_format" in config_options[
        "global"] else "zstd"
    config_output["backend"]["compressionFormat"] = compression_format
    config_output["backend"]["connectionPooling"] = {}
    if config_options["global"]["connection_pooling"] == "on":
        config_output["backend"]["connectionPooling"]["enabled"] = True
        config_output["backend"]["connectionPooling"]["poolSize"] = config_options["global"]["connection_pool_size"]
    else:
        config_output["backend"]["connectionPooling"]["enabled"] = False
        config_output["backend"]["connectionPooling"]["poolSize"] = 0

    if config_options["global"]["in_cluster"]:
        config_output["kubernetes"] = {}
        config_output["kubernetes"]["client"] = {}
        config_output["kubernetes"]["client"]["outOfCluster"] = "${KUBERNETES_CLIENT_OUT_OF_CLUSTER:false}"
        config_output["kubernetes"]["processor"] = {}
        annotation_prefix = config_options["annotations"]["annotation_prefix"] if "annotation_prefix" in config_options[
            "annotations"] else "ANNOTATIONS_DISABLED"
        config_output["kubernetes"]["processor"][
            "annotationsPrefix"] = "${KUBERNETES_PROCESSOR_ANNOTATIONS_PREFIX:\"" + annotation_prefix + "\"}"

    config_output["discovery"] = {}
    config_output["discovery"]["kubernetes"] = {}
    config_output["discovery"]["kubernetes"]["enabled"] = config_options["global"]["in_cluster"]
    if config_options["global"]["in_cluster"]:
        if config_options["monitor_cadvisor"] or config_options["monitor_kubelet"] or config_options["monitor_probes"]:
            config_output["discovery"]["kubernetes"]["kubeletMonitoring"] = {}
            config_output["discovery"]["kubernetes"]["kubeletMonitoring"]["port"] = 10250
            config_output["discovery"]["kubernetes"]["kubeletMonitoring"][
                "bearerTokenFile"] = "/var/run/secrets/kubernetes.io/serviceaccount/token"
            config_output["discovery"]["kubernetes"]["kubeletMonitoring"]["labelsToAugment"] = []
            config_output["discovery"]["kubernetes"]["kubeletMonitoring"]["annotationsToAugment"] = []
            config_output["discovery"]["kubernetes"]["kubeletMonitoring"]["kubeletMetricsEnabled"] = config_options[
                "monitor_kubelet"]
            config_output["discovery"]["kubernetes"]["kubeletMonitoring"]["cadvisorMetricsEnabled"] = config_options[
                "monitor_cadvisor"]
            config_output["discovery"]["kubernetes"]["kubeletMonitoring"]["probesMetricsEnabled"] = config_options[
                "monitor_probes"]

        config_output["discovery"]["kubernetes"]["serviceMonitorsEnabled"] = config_options["use_service_monitors"]
        config_output["discovery"]["kubernetes"]["endpointsDiscoveryEnabled"] = config_options["use_service_monitors"]
        config_output["discovery"]["kubernetes"]["useEndpointSlices"] = config_options["use_service_monitors"]
        config_output["discovery"]["kubernetes"]["kubeSystemEndpointsDiscoveryEnabled"] = config_options[
            "monitor_kube_system"]
        if config_options["use_service_monitors"] and not config_options["use_annotations"]:
            config_output["discovery"]["kubernetes"]["podMatchingStrategy"] = "service_monitors_only"
        elif config_options["use_service_monitors"] and config_options["use_annotations"]:
            config_output["discovery"]["kubernetes"]["podMatchingStrategy"] = "service_monitors_first"
        elif not config_options["use_service_monitors"] and config_options["use_annotations"]:
            config_output["discovery"]["kubernetes"]["podMatchingStrategy"] = "annotations_first"
        else:
            config_output["discovery"]["kubernetes"]["podMatchingStrategy"] = "service_monitors_only"

    config_output["discovery"]["prometheus"] = {}

    # enable prometheus sd if there are prometheus jobs or if annotations are disabled
    prometheus_sd_enabled = len(config_options["prometheus_jobs"]) > 0 or not config_options["use_annotations"]
    config_output["discovery"]["prometheus"]["enabled"] = prometheus_sd_enabled
    if prometheus_sd_enabled:
        # if annotations are enabled, the collector self scrape is handled by the annotations processor
        # if annotations are not enabled, the collector self scrape is handled by the prometheus sd
        instance = "${KUBERNETES_POD_NAME:\"\"}" if config_options["global"]["in_cluster"] else "${HOSTNAME:\"\"}"
        if not config_options["use_annotations"]:
            config_output["discovery"]["prometheus"]["scrape_configs"] = [
                {
                    "job_name": "chronocollector",
                    "scrape_interval": config_options["global"]["scrape_interval"],
                    "scrape_timeout": config_options["global"]["scrape_timeout"],
                    "static_configs": [
                        {
                            "targets": ["localhost:3030"]
                        }
                    ],
                    "relabel_configs": [
                        {
                            "target_label": "instance",
                            "replacement": instance,
                            "action": "replace"
                        }
                    ]
                }
            ]
        else:
            config_output["discovery"]["prometheus"]["scrape_configs"] = []
        new_prometheus_jobs = [
            {
                "job_name": job["job_name"],
                "scrape_interval": job["scrape_interval"],
                "scrape_timeout": job["scrape_timeout"],
                "static_configs": [
                    {
                        "targets": job["targets"].split(",")
                    }
                ],
                "relabel_configs": [
                    {
                        "target_label": "instance",
                        "replacement": instance,
                        "action": "replace"
                    }
                ]
            }
            for job in config_options["prometheus_jobs"]
        ]
        config_output["discovery"]["prometheus"]["scrape_configs"].extend(new_prometheus_jobs)

    if config_options["use_service_monitors"]:
        config_output["serviceMonitor"] = {}
        config_output["serviceMonitor"] = {
            "allowSkipPodInfo": True if config_options["deployment_type"] == "deployment" else False,
            "serviceMonitorSelector": {
                "matchAll": config_options["discover_all_service_monitors"],
                "matchExpressions": [
                    {
                        "label": service_monitor["match_label"],
                        "operator": "In",
                        "values": [
                            service_monitor["match_value"]
                        ]
                    }
                    for service_monitor in config_options["service_monitors"]
                ]
            }
        }

    config_output["scrape"] = {}
    config_output["scrape"]["defaults"] = {}
    config_output["scrape"]["defaults"]["scrapeInterval"] = config_options["global"]["scrape_interval"]
    config_output["scrape"]["defaults"]["scrapeTimeout"] = config_options["global"]["scrape_timeout"]
    if config_options["global"]["staleness_markers"] == "on":
        config_output["scrape"]["enableStalenessMarker"] = True

    if config_options["global"]["ingestion_buffering"] == "on":
        config_output["ingestionBuffering"] = {}
        config_output["ingestionBuffering"]["retry"] = {}
        config_output["ingestionBuffering"]["retry"]["enabled"] = True
        config_output["ingestionBuffering"]["retry"]["directory"] = config_options["global"][
            "ingestion_buffering_directory"]
        config_output["ingestionBuffering"]["retry"]["defaultTTLInSeconds"] = config_options["global"][
            "ingestion_buffering_ttl"]
        config_output["ingestionBuffering"]["retry"]["maxBufferSizeMB"] = config_options["global"][
            "ingestion_buffering_max_size"]

    if config_options["dogstatsd"]["enabled"]:
        config_output["push"] = {}
        config_output["push"]["dogstatsd"] = {}
        config_output["push"]["dogstatsd"]["enabled"] = True
        config_output["push"]["dogstatsd"]["listenAddress"] = config_options["dogstatsd"]["listenAddress"]
        config_output["push"]["dogstatsd"]["mode"] = config_options["dogstatsd"]["mode"]
        config_output["push"]["dogstatsd"]["nameLabelName"] = config_options["dogstatsd"]["nameLabelName"]
        if len(config_options["dogstatsd"]["labels"]) > 0:
            config_output["push"]["dogstatsd"]["labels"] = {}
            for label in config_options["dogstatsd"]["labels"]:
                config_output["push"]["dogstatsd"]["labels"][label["key"]] = label["value"]
        if config_options["dogstatsd"]["prefix"]:
            config_output["push"]["dogstatsd"]["prefix"] = config_options["dogstatsd"]["prefix"]
        if config_options["dogstatsd"]["aggregations"]["enabled"]:
            config_output["push"]["dogstatsd"]["aggregations"] = {}
            config_output["push"]["dogstatsd"]["aggregations"]["counters"] = {}
            config_output["push"]["dogstatsd"]["aggregations"]["counters"]["interval"] = \
                config_options["dogstatsd"]["aggregations"]["counters"]["interval"]
            config_output["push"]["dogstatsd"]["aggregations"]["gauges"] = {}
            config_output["push"]["dogstatsd"]["aggregations"]["gauges"]["interval"] = \
                config_options["dogstatsd"]["aggregations"]["gauges"]["interval"]
            config_output["push"]["dogstatsd"]["aggregations"]["timers"] = {}
            config_output["push"]["dogstatsd"]["aggregations"]["timers"]["interval"] = \
                config_options["dogstatsd"]["aggregations"]["timers"]["interval"]
            config_output["push"]["dogstatsd"]["aggregations"]["inactiveExpireAt"] = \
                config_options["dogstatsd"]["aggregations"]["inactiveExpireAt"]

    if config_options["statsd"]["enabled"]:
        if "push" not in config_output:
            config_output["push"] = {}
        config_output["push"]["statsd"] = {}
        config_output["push"]["statsd"]["enabled"] = True
        config_output["push"]["statsd"]["listenAddress"] = config_options["statsd"]["listenAddress"]

    if config_options["carbon"]["enabled"]:
        if "push" not in config_output:
            config_output["push"] = {}
        config_output["push"]["carbon"] = {}
        config_output["push"]["carbon"]["enabled"] = True
        config_output["push"]["carbon"]["listenAddress"] = config_options["carbon"]["listenAddress"]

    if config_options["prometheus"]["enabled"]:
        if "push" not in config_output:
            config_output["push"] = {}
        config_output["push"]["importPrometheus"] = {}
        config_output["push"]["importPrometheus"]["enabled"] = True

    if config_options["openmetrics"]["enabled"]:
        if "push" not in config_output:
            config_output["push"] = {}
        config_output["push"]["importOpenMetrics"] = {}
        config_output["push"]["importOpenMetrics"]["enabled"] = True

    if config_options["pushgateway"]["enabled"]:
        if "push" not in config_output:
            config_output["push"] = {}
        config_output["push"]["prometheusRemoteWrite"] = {}
        config_output["push"]["prometheusRemoteWrite"]["enabled"] = True

    if config_options["otel"]["enabled"] or config_options["jaeger"]["enabled"] or config_options["zipkin"]["enabled"]:
        config_output["spans"] = {}
        config_output["spans"]["enabled"] = True
        config_output["spans"]["compression"] = {}
        config_output["spans"]["compression"]["enabled"] = True
        if config_options["otel"]["enabled"]:
            config_output["spans"]["otel"] = {}
            config_output["spans"]["otel"]["enabled"] = True
            config_output["spans"]["otel"]["listenAddress"] = config_options["otel"]["listenAddress"]
            if config_options["otel"]["httpEnabled"]:
                config_output["spans"]["otel"]["httpEnabled"] = True
                config_output["spans"]["otel"]["httpListenAddress"] = config_options["otel"]["httpListenAddress"]
        if config_options["jaeger"]["enabled"]:
            config_output["spans"]["jaeger"] = {}
            config_output["spans"]["jaeger"]["enabled"] = True
            config_output["spans"]["jaeger"]["listenAddress"] = config_options["jaeger"]["listenAddress"]
        if config_options["zipkin"]["enabled"]:
            config_output["spans"]["zipkin"] = {}
            config_output["spans"]["zipkin"]["enabled"] = True
            config_output["spans"]["zipkin"]["listenAddress"] = config_options["zipkin"]["listenAddress"]

    return config_output


def create_config_file(config_options, config_output):
    if config_options["deployment_type"] == "standalone":
        return yaml.dump(config_output)

    class AsLiteral(str):
        pass

    def represent_literal(dumper, data):
        return dumper.represent_scalar(BaseResolver.DEFAULT_SCALAR_TAG,
                                       data, style="|")

    yaml.add_representer(AsLiteral, represent_literal)

    if config_options["deployment_type"] == "daemonset":
        base_txt = open("builder/chronocollector-daemonset-base.yaml").read()
        base_txt = base_txt \
            .replace("chronocollector-daemonset", config_options["global"]["collector_name"]) \
            .replace("namespace: default", f"namespace: {config_options['global']['collector_namespace']}") \
            .replace("prometheus.io/scrape", f"{config_options['annotations']['annotation_prefix']}scrape") \
            .replace("prometheus.io/port", f"{config_options['annotations']['annotation_prefix']}port")
        base_yaml = yaml.safe_load_all(base_txt)
    if config_options["deployment_type"] == "deployment":
        base_txt = open("builder/chronocollector-deployment-base.yaml").read()
        base_txt = base_txt \
            .replace("chronocollector-deployment", config_options["global"]["collector_name"]) \
            .replace("namespace: default", f"namespace: {config_options['global']['collector_namespace']}") \
            .replace("prometheus.io/scrape", f"{config_options['annotations']['annotation_prefix']}scrape") \
            .replace("prometheus.io/port", f"{config_options['annotations']['annotation_prefix']}port")
        base_yaml = yaml.safe_load_all(base_txt)

    base_yaml = list(base_yaml)

    if config_options["otel"]["enabled"] \
            or config_options["jaeger"]["enabled"] \
            or config_options["zipkin"]["enabled"] \
            or config_options["dogstatsd"]["enabled"] \
            or config_options["statsd"]["enabled"] \
            or config_options["carbon"]["enabled"] \
            or config_options["prometheus"]["enabled"] \
            or config_options["openmetrics"]["enabled"] \
            or config_options["pushgateway"]["enabled"]:
        service = {}
        service["apiVersion"] = "v1"
        service["kind"] = "Service"
        service["metadata"] = {}
        service["metadata"]["labels"] = {}
        service["metadata"]["labels"]["app"] = config_options["global"]["collector_name"]
        service["metadata"]["name"] = f"{config_options['global']['collector_name']}"
        service["metadata"]["namespace"] = config_options["global"]["collector_namespace"]
        service["spec"] = {}
        service["spec"]["clusterIP"] = "None"
        service["spec"]["ports"] = []
        service["spec"]["selector"] = {}
        service["spec"]["selector"]["app"] = config_options["global"]["collector_name"]
        base_yaml.append(service)

    for doc in base_yaml:
        if doc["kind"] == "Deployment" or doc["kind"] == "DaemonSet":
            doc["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] = config_options["global"][
                "limit_cpu"]
            doc["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"] = \
                config_options["global"]["limit_memory"]
            doc["spec"]["template"]["spec"]["containers"][0]["resources"]["requests"]["cpu"] = config_options["global"][
                "request_cpu"]
            doc["spec"]["template"]["spec"]["containers"][0]["resources"]["requests"]["memory"] = \
                config_options["global"]["request_memory"]

            doc["spec"]["template"]["spec"]["containers"][0][
                "image"] = f"gcr.io/chronosphereio/chronocollector:{config_options['global']['chronocollector_image_version']}"

            if config_options["otel"]["enabled"]:
                doc["spec"]["template"]["spec"]["containers"][0]["ports"].append({
                    "containerPort": int(config_options["otel"]["listenAddress"].split(":")[1]),
                    "name": "otel",
                    "protocol": "TCP"
                })
                if config_options["otel"]["httpEnabled"]:
                    doc["spec"]["template"]["spec"]["containers"][0]["ports"].append({
                        "containerPort": int(config_options["otel"]["httpListenAddress"].split(":")[1]),
                        "name": "otel-http",
                        "protocol": "TCP"
                    })
            if config_options["jaeger"]["enabled"]:
                doc["spec"]["template"]["spec"]["containers"][0]["ports"].append({
                    "containerPort": int(config_options["jaeger"]["listenAddress"].split(":")[1]),
                    "name": "jaeger",
                    "protocol": "TCP"
                })
            if config_options["zipkin"]["enabled"]:
                doc["spec"]["template"]["spec"]["containers"][0]["ports"].append({
                    "containerPort": int(config_options["zipkin"]["listenAddress"].split(":")[1]),
                    "name": "zipkin",
                    "protocol": "TCP"
                })
            if config_options["dogstatsd"]["enabled"]:
                doc["spec"]["template"]["spec"]["containers"][0]["ports"].append({
                    "containerPort": int(config_options["dogstatsd"]["listenAddress"].split(":")[1]),
                    "name": "dogstatsd",
                    "protocol": "UDP"
                })
            if config_options["statsd"]["enabled"]:
                doc["spec"]["template"]["spec"]["containers"][0]["ports"].append({
                    "containerPort": int(config_options["statsd"]["listenAddress"].split(":")[1]),
                    "name": "statsd",
                    "protocol": "UDP"
                })
            if config_options["carbon"]["enabled"]:
                doc["spec"]["template"]["spec"]["containers"][0]["ports"].append({
                    "containerPort": int(config_options["carbon"]["listenAddress"].split(":")[1]),
                    "name": "carbon",
                    "protocol": "UDP"
                })

        if doc["kind"] == "Service":
            if config_options["otel"]["enabled"]:
                doc["spec"]["ports"].append({
                    "name": "otel",
                    "port": int(config_options["otel"]["listenAddress"].split(":")[1]),
                    "protocol": "TCP",
                    "targetPort": "otel"
                })
                if config_options["otel"]["httpEnabled"]:
                    doc["spec"]["ports"].append({
                        "name": "otel-http",
                        "port": int(config_options["otel"]["httpListenAddress"].split(":")[1]),
                        "protocol": "TCP",
                        "targetPort": "otel-http"
                    })
            if config_options["jaeger"]["enabled"]:
                doc["spec"]["ports"].append({
                    "name": "jaeger",
                    "port": int(config_options["jaeger"]["listenAddress"].split(":")[1]),
                    "protocol": "TCP",
                    "targetPort": "jaeger"
                })
            if config_options["zipkin"]["enabled"]:
                doc["spec"]["ports"].append({
                    "name": "zipkin",
                    "port": int(config_options["zipkin"]["listenAddress"].split(":")[1]),
                    "protocol": "TCP",
                    "targetPort": "zipkin"
                })
            if config_options["dogstatsd"]["enabled"]:
                doc["spec"]["ports"].append({
                    "name": "dogstatsd",
                    "port": int(config_options["dogstatsd"]["listenAddress"].split(":")[1]),
                    "protocol": "UDP",
                    "targetPort": "dogstatsd"
                })
            if config_options["statsd"]["enabled"]:
                doc["spec"]["ports"].append({
                    "name": "statsd",
                    "port": int(config_options["statsd"]["listenAddress"].split(":")[1]),
                    "protocol": "UDP",
                    "targetPort": "statsd"
                })
            if config_options["carbon"]["enabled"]:
                doc["spec"]["ports"].append({
                    "name": "carbon",
                    "port": int(config_options["carbon"]["listenAddress"].split(":")[1]),
                    "protocol": "UDP",
                    "targetPort": "carbon"
                })
            if config_options["prometheus"]["enabled"] or config_options["openmetrics"]["enabled"] or \
                    config_options["pushgateway"]["enabled"]:
                doc["spec"]["ports"].append({
                    "name": "http",
                    "port": 3030,
                    "protocol": "TCP",
                    "targetPort": "http"
                })

        if doc["kind"] == "ClusterRole":
            if not config_options["use_service_monitors"]:
                rules = doc["rules"]
                rules_to_keep = []
                for rule in rules:
                    if "resources" in rule and "servicemonitors" in rule["resources"]:
                        continue
                    else:
                        rules_to_keep.append(rule)
                doc["rules"] = rules_to_keep

    if config_options["deployment_type"] == "daemonset" or config_options["deployment_type"] == "deployment":
        for doc in base_yaml:
            if doc["kind"] == "Secret":
                if config_options["global"]["tenant"] == "<tenant>":
                    doc["data"]["address"] = "<tenant>"
                else:
                    doc["data"]["address"] = base64Encode(config_options["global"]["tenant"])
                if config_options["global"]["api_token"] == "<api_token>":
                    doc["data"]["api-token"] = "<api_token>"
                else:
                    doc["data"]["api-token"] = base64Encode(config_options["global"]["api_token"])

            if doc["kind"] == "ConfigMap":
                doc["data"]["config.yml"] = AsLiteral(yaml.dump(config_output))

    return yaml.dump_all(base_yaml)


def finalize(config_options, finish_tab):
    with finish_tab:

        manifest_tab, helm_tab = st.tabs(["Manifest", "Helm"])

        with manifest_tab:

            if config_options["block_submit"]:
                if not config_options["global"]["tenant"] == "<tenant>":
                    st.warning("Tenant is invalid")
                if not config_options["global"]["api_token"] == "<api_token>":
                    st.warning("Api token is invalid")

            if not config_options["global"]["in_cluster"]:
                st.markdown("To run the collector, run the following command:")
                st.code(
                    "GATEWAY_ADDRESS={} API_TOKEN={} PATH_TO_FILE/COLLECTOR_BINARY -f PATH_TO_FILE/chronocollector.yaml".format(
                        config_options["global"]["tenant"], config_options["global"]["api_token"]))
            else:
                st.markdown("To deploy the collector, run the following command:")
                st.code(f"kubectl apply -f PATH_TO_FILE/{config_options['global']['collector_name']}.yaml")

            config_output = generate_config(config_options)
            output_yaml = create_config_file(config_options, config_output)

            logger.info(f"config generated for tenant {config_options['global']['tenant']}")

            st.download_button(
                label="Download Config",
                data=output_yaml,
                file_name=f"{config_options['global']['collector_name']}.yaml",
                mime="text/yaml"
            )

            st.code(output_yaml, language="yaml", line_numbers=True)

        with helm_tab:

            if config_options["block_submit"]:
                if config_options["global"]["tenant"] == "<tenant>":
                    st.warning("Tenant is invalid")
                if config_options["global"]["api_token"] == "<api_token>":
                    st.warning("Api token is invalid")

            try:
                with st.spinner("Generating helm chart..."):

                    if config_options["global"]["tenant"] == "<tenant>":
                        output_yaml = output_yaml.replace("address: <tenant>", f"address: {base64Encode('foo')}")
                    if config_options["global"]["api_token"] == "<api_token>":
                        output_yaml = output_yaml.replace("api-token: <api_token>", f"api-token: {base64Encode('bar')}")

                    with open(f"{config_options['global']['collector_name']}.yaml", "w") as f:
                        f.write(output_yaml)
                    subprocess.check_output(["helmify", "-f", f"{config_options['global']['collector_name']}.yaml",
                                             f"{config_options['global']['collector_name']}"])
                    shutil.make_archive(f"{config_options['global']['collector_name']}", "zip",
                                        f"{config_options['global']['collector_name']}")
                    data = open(f"{config_options['global']['collector_name']}.zip", "rb")
                    if data is not None:
                        st.download_button(
                            label="Download Helm Chart",
                            data=data,
                            file_name=f"{config_options['global']['collector_name']}.zip",
                            mime="application/zip"
                        )
                    else:
                        st.error("Error generating helm chart.")
            except Exception as e:
                logger.error(e)
                st.error("Error generating helm chart, likely due to unset tenant or api token.")

            try:
                os.remove(f"{config_options['global']['collector_name']}.zip")
            except:
                pass
            try:
                shutil.rmtree(f"{config_options['global']['collector_name']}")
            except:
                pass
            try:
                os.remove(f"{config_options['global']['collector_name']}.yaml")
            except:
                pass

            camel_case_name = ''.join(
                x for x in config_options['global']['collector_name'].title().replace("-", "") if not x.isspace())
            camel_case_name = camel_case_name[0].lower() + camel_case_name[1:]

            st.markdown(f"Unzip the helm chart")
            st.code(f"tar -xvf {config_options['global']['collector_name']}.tgz")

            st.markdown("Set the following environment variables:")

            st.code(f"""export CHRONOSPHERE_ORG_NAME={config_options['global']['tenant'].split('.')[0]}
export CHRONOSPHERE_API_TOKEN={config_options['global']['api_token']}""")

            st.markdown("Then run:")

            st.code(f"""helm install \\
    --set {camel_case_name}.address=${{CHRONOSPHERE_ORG_NAME}}.chronosphere.io:443 \\
    --set {camel_case_name}.apiToken=${{CHRONOSPHERE_API_TOKEN}} \\
    --namespace {config_options['global']['collector_namespace']} \\
    {config_options['global']['collector_name']} \\
    ./{config_options['global']['collector_name']}""")


if __name__ == '__main__':
    st.set_page_config(
        page_title="Chronosphere Config Builder",
    )
    st.markdown(
        f"""
                <style>
                    h1{{
                        text-align: center;
                    }}
                    .stTextArea textarea {{ 
                        font-family: monospace;
                        font-size: 15px; 
                    }}
                    .block-container{{
                        min-width: 1000px;
                    }}
                    div[role="radiogroup"] >  :first-child{{
                        display: none !important;
                    }}
                </style>
                """,
        unsafe_allow_html=True,
    )
    Path("logs").mkdir(parents=True, exist_ok=True)
    logger.add("logs/chronosphere.log", level="INFO")
    main()
