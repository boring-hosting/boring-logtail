// SPDX-License-Identifier: GPL-3.0-or-later

//! OTLP/gRPC adapter for the in-cluster collector.

use std::{collections::BTreeMap, time::SystemTime};

use async_trait::async_trait;
use opentelemetry_proto::tonic::{
    collector::metrics::v1::{
        ExportMetricsServiceRequest, metrics_service_client::MetricsServiceClient,
    },
    common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value},
    metrics::v1::{
        Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, metric, number_data_point,
    },
    resource::v1::Resource,
};
use tonic::{Code, Request, transport::Channel};

use crate::{
    config::CollectorConfig,
    ports::{
        CpuStats, MemoryStats, MetricsPushError, MetricsSink, PodReference, StatsSnapshot,
        VolumeStats,
    },
};

pub struct OtlpMetricsAdapter {
    client: MetricsServiceClient<Channel>,
    timeout: std::time::Duration,
}

impl OtlpMetricsAdapter {
    pub fn new(config: &CollectorConfig) -> Result<Self, MetricsPushError> {
        let channel = Channel::from_shared(config.endpoint.clone())
            .map_err(|error| MetricsPushError::Rejected(format!("collector endpoint: {error}")))?
            .connect_lazy();
        Ok(Self {
            client: MetricsServiceClient::new(channel),
            timeout: config.timeout,
        })
    }
}

#[async_trait]
impl MetricsSink for OtlpMetricsAdapter {
    async fn push(&self, snapshot: StatsSnapshot) -> Result<(), MetricsPushError> {
        let request = export_request(snapshot)?;
        if request.resource_metrics[0].scope_metrics[0]
            .metrics
            .is_empty()
        {
            return Ok(());
        }

        let mut request = Request::new(request);
        request.set_timeout(self.timeout);
        self.client
            .clone()
            .export(request)
            .await
            .map_err(|status| match status.code() {
                Code::Cancelled
                | Code::DeadlineExceeded
                | Code::ResourceExhausted
                | Code::Unavailable
                | Code::Unknown => {
                    MetricsPushError::Unavailable(format!("collector OTLP export: {status}"))
                }
                _ => MetricsPushError::Rejected(format!("collector OTLP export: {status}")),
            })?;
        Ok(())
    }
}

fn export_request(
    snapshot: StatsSnapshot,
) -> Result<ExportMetricsServiceRequest, MetricsPushError> {
    let node_name = snapshot.node.name.clone();
    let mut points = BTreeMap::<String, Vec<NumberDataPoint>>::new();
    let node_attributes = BTreeMap::from([("k8s_node_name", node_name.clone())]);
    append_stats(
        &mut points,
        "k8s_node",
        &node_attributes,
        snapshot.node.cpu.as_ref(),
        snapshot.node.memory.as_ref(),
    )?;

    for pod in snapshot.pods {
        let pod_attributes = pod_attributes(&node_name, &pod.reference);
        append_stats(
            &mut points,
            "k8s_pod",
            &pod_attributes,
            pod.cpu.as_ref(),
            pod.memory.as_ref(),
        )?;
        for volume in pod.volumes {
            append_volume_stats(&mut points, &pod_attributes, &volume)?;
        }
        for container in pod.containers {
            let mut attributes = pod_attributes.clone();
            attributes.insert("k8s_container_name", container.name);
            append_stats(
                &mut points,
                "k8s_container",
                &attributes,
                container.cpu.as_ref(),
                container.memory.as_ref(),
            )?;
        }
    }

    let metrics = points
        .into_iter()
        .map(|(name, data_points)| Metric {
            name,
            data: Some(metric::Data::Gauge(Gauge { data_points })),
            ..Metric::default()
        })
        .collect();
    Ok(ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: vec![
                    attribute("service.name", "boring-probe"),
                    attribute("service.instance.id", node_name),
                ],
                ..Resource::default()
            }),
            scope_metrics: vec![ScopeMetrics {
                scope: Some(InstrumentationScope {
                    name: "boring-probe".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                    ..InstrumentationScope::default()
                }),
                metrics,
                ..ScopeMetrics::default()
            }],
            ..ResourceMetrics::default()
        }],
    })
}

fn append_volume_stats(
    metrics: &mut BTreeMap<String, Vec<NumberDataPoint>>,
    pod_attributes: &BTreeMap<&'static str, String>,
    volume: &VolumeStats,
) -> Result<(), MetricsPushError> {
    let mut attributes = pod_attributes.clone();
    attributes.insert("k8s_volume_name", volume.name.clone());
    if let Some(claim) = &volume.persistent_volume_claim {
        attributes.insert("k8s_persistent_volume_claim_name", claim.name.clone());
        attributes.insert(
            "k8s_persistent_volume_claim_namespace",
            claim.namespace.clone(),
        );
    }
    for (suffix, value) in [
        ("available_bytes", volume.available_bytes),
        ("capacity_bytes", volume.capacity_bytes),
        ("used_bytes", volume.used_bytes),
        ("inodes_free", volume.inodes_free),
        ("inodes", volume.inodes),
        ("inodes_used", volume.inodes_used),
    ] {
        append_optional(
            metrics,
            format!("k8s_volume_filesystem_{suffix}"),
            &attributes,
            volume.observed_at,
            value.map(|value| value as f64),
        )?;
    }
    Ok(())
}

fn pod_attributes(node: &str, pod: &PodReference) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("k8s_namespace_name", pod.namespace.clone()),
        ("k8s_node_name", node.to_owned()),
        ("k8s_pod_name", pod.name.clone()),
        ("k8s_pod_uid", pod.uid.clone()),
    ])
}

fn append_stats(
    metrics: &mut BTreeMap<String, Vec<NumberDataPoint>>,
    prefix: &str,
    attributes: &BTreeMap<&'static str, String>,
    cpu: Option<&CpuStats>,
    memory: Option<&MemoryStats>,
) -> Result<(), MetricsPushError> {
    if let Some(cpu) = cpu {
        append_optional(
            metrics,
            format!("{prefix}_cpu_usage_cores"),
            attributes,
            cpu.observed_at,
            cpu.usage_nano_cores
                .map(|value| value as f64 / 1_000_000_000.0),
        )?;
        append_optional(
            metrics,
            format!("{prefix}_cpu_time_seconds_total"),
            attributes,
            cpu.observed_at,
            cpu.usage_core_nano_seconds
                .map(|value| value as f64 / 1_000_000_000.0),
        )?;
    }
    if let Some(memory) = memory {
        for (suffix, value) in [
            ("available_bytes", memory.available_bytes),
            ("usage_bytes", memory.usage_bytes),
            ("working_set_bytes", memory.working_set_bytes),
            ("rss_bytes", memory.rss_bytes),
            ("page_faults_total", memory.page_faults),
            ("major_page_faults_total", memory.major_page_faults),
        ] {
            append_optional(
                metrics,
                format!("{prefix}_memory_{suffix}"),
                attributes,
                memory.observed_at,
                value.map(|value| value as f64),
            )?;
        }
    }
    Ok(())
}

fn append_optional(
    metrics: &mut BTreeMap<String, Vec<NumberDataPoint>>,
    name: String,
    attributes: &BTreeMap<&'static str, String>,
    observed_at: SystemTime,
    value: Option<f64>,
) -> Result<(), MetricsPushError> {
    let Some(value) = value else {
        return Ok(());
    };
    metrics.entry(name).or_default().push(NumberDataPoint {
        attributes: attributes
            .iter()
            .map(|(key, value)| attribute(*key, value.clone()))
            .collect(),
        time_unix_nano: unix_nanos(observed_at)?,
        value: Some(number_data_point::Value::AsDouble(value)),
        ..NumberDataPoint::default()
    });
    Ok(())
}

fn attribute(key: impl Into<String>, value: impl Into<String>) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.into())),
        }),
        ..KeyValue::default()
    }
}

fn unix_nanos(time: SystemTime) -> Result<u64, MetricsPushError> {
    let nanos = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| MetricsPushError::Rejected("measurement predates Unix epoch".to_owned()))?
        .as_nanos();
    u64::try_from(nanos)
        .map_err(|_| MetricsPushError::Rejected("measurement timestamp is too large".to_owned()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::ports::{
        ContainerStats, NodeStats, PersistentVolumeClaimReference, PodStats, VolumeStats,
    };

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn maps_present_measurements_to_otlp_metrics() {
        let request = export_request(StatsSnapshot {
            node: NodeStats {
                name: "worker-a".to_owned(),
                start_time: at(1),
                cpu: Some(CpuStats {
                    observed_at: at(10),
                    usage_nano_cores: Some(250_000_000),
                    usage_core_nano_seconds: Some(9_000_000_000),
                }),
                memory: None,
            },
            pods: vec![PodStats {
                reference: PodReference {
                    name: "game-0".to_owned(),
                    namespace: "games".to_owned(),
                    uid: "pod-1".to_owned(),
                },
                start_time: at(2),
                cpu: None,
                memory: None,
                volumes: vec![VolumeStats {
                    name: "data".to_owned(),
                    persistent_volume_claim: Some(PersistentVolumeClaimReference {
                        name: "game-data".to_owned(),
                        namespace: "games".to_owned(),
                    }),
                    observed_at: at(12),
                    available_bytes: Some(4096),
                    capacity_bytes: Some(8192),
                    used_bytes: Some(3072),
                    inodes_free: Some(90),
                    inodes: Some(100),
                    inodes_used: Some(10),
                }],
                containers: vec![ContainerStats {
                    name: "server".to_owned(),
                    start_time: at(3),
                    cpu: None,
                    memory: Some(MemoryStats {
                        observed_at: at(11),
                        available_bytes: None,
                        usage_bytes: Some(2048),
                        working_set_bytes: None,
                        rss_bytes: None,
                        page_faults: None,
                        major_page_faults: None,
                    }),
                }],
            }],
        })
        .unwrap();

        let resource = &request.resource_metrics[0];
        let metrics = &resource.scope_metrics[0].metrics;
        assert_eq!(metrics.len(), 9);
        let cpu = metrics
            .iter()
            .find(|metric| metric.name == "k8s_node_cpu_usage_cores")
            .unwrap();
        let metric::Data::Gauge(gauge) = cpu.data.as_ref().unwrap() else {
            panic!("expected gauge")
        };
        assert_eq!(gauge.data_points[0].time_unix_nano, 10_000_000_000);
        assert_eq!(
            gauge.data_points[0].value,
            Some(number_data_point::Value::AsDouble(0.25))
        );
        let capacity = metrics
            .iter()
            .find(|metric| metric.name == "k8s_volume_filesystem_capacity_bytes")
            .unwrap();
        let metric::Data::Gauge(gauge) = capacity.data.as_ref().unwrap() else {
            panic!("expected gauge")
        };
        assert!(gauge.data_points[0].attributes.iter().any(|attribute| {
            attribute.key == "k8s_persistent_volume_claim_name"
                && attribute
                    .value
                    .as_ref()
                    .and_then(|value| value.value.as_ref())
                    == Some(&any_value::Value::StringValue("game-data".to_owned()))
        }));
    }

    #[test]
    fn omits_missing_measurements_without_inventing_zeroes() {
        let attributes = BTreeMap::from([("k8s_pod_uid", "pod-1".to_owned())]);
        let volume = VolumeStats {
            name: "data".to_owned(),
            persistent_volume_claim: None,
            observed_at: at(12),
            available_bytes: None,
            capacity_bytes: Some(8192),
            used_bytes: None,
            inodes_free: None,
            inodes: None,
            inodes_used: None,
        };
        let mut metrics = BTreeMap::new();

        append_volume_stats(&mut metrics, &attributes, &volume).unwrap();

        assert_eq!(metrics.len(), 1);
        assert!(metrics.contains_key("k8s_volume_filesystem_capacity_bytes"));
    }
}
