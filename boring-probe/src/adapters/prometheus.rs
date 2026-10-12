// SPDX-License-Identifier: GPL-3.0-or-later

//! Prometheus Remote Write 1.0 adapter.

use std::{collections::BTreeMap, time::SystemTime};

use async_trait::async_trait;
use prost::Message;
use reqwest::header::{CONTENT_ENCODING, CONTENT_TYPE, USER_AGENT};

use crate::{
    config::PrometheusConfig,
    ports::{CpuStats, MemoryStats, MetricsPushError, MetricsSink, PodReference, StatsSnapshot},
};

const REMOTE_WRITE_VERSION_HEADER: &str = "X-Prometheus-Remote-Write-Version";

pub struct PrometheusRemoteWriteAdapter {
    client: reqwest::Client,
    endpoint: String,
    timeout: std::time::Duration,
}

impl PrometheusRemoteWriteAdapter {
    pub fn new(config: &PrometheusConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint: config.endpoint.clone(),
            timeout: config.timeout,
        }
    }
}

#[async_trait]
impl MetricsSink for PrometheusRemoteWriteAdapter {
    async fn push(&self, snapshot: StatsSnapshot) -> Result<(), MetricsPushError> {
        let request = write_request(snapshot)?;
        if request.timeseries.is_empty() {
            return Ok(());
        }

        let encoded = request.encode_to_vec();
        let compressed = snap::raw::Encoder::new()
            .compress_vec(&encoded)
            .map_err(|error| MetricsPushError::Rejected(format!("encode Snappy body: {error}")))?;
        let response = self
            .client
            .post(&self.endpoint)
            .timeout(self.timeout)
            .header(CONTENT_ENCODING, "snappy")
            .header(CONTENT_TYPE, "application/x-protobuf")
            .header(
                USER_AGENT,
                concat!("boring-probe/", env!("CARGO_PKG_VERSION")),
            )
            .header(REMOTE_WRITE_VERSION_HEADER, "0.1.0")
            .body(compressed)
            .send()
            .await
            .map_err(|error| MetricsPushError::Unavailable(format!("remote write: {error}")))?;

        match response.status().as_u16() {
            200..=299 => Ok(()),
            429 | 500..=599 => Err(MetricsPushError::Unavailable(format!(
                "remote write returned HTTP {}",
                response.status()
            ))),
            _ => Err(MetricsPushError::Rejected(format!(
                "remote write returned HTTP {}",
                response.status()
            ))),
        }
    }
}

#[derive(Clone, PartialEq, Message)]
struct WriteRequest {
    #[prost(message, repeated, tag = "1")]
    timeseries: Vec<TimeSeries>,
}

#[derive(Clone, PartialEq, Message)]
struct TimeSeries {
    #[prost(message, repeated, tag = "1")]
    labels: Vec<Label>,
    #[prost(message, repeated, tag = "2")]
    samples: Vec<Sample>,
}

#[derive(Clone, PartialEq, Message)]
struct Label {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    value: String,
}

#[derive(Clone, PartialEq, Message)]
struct Sample {
    #[prost(double, tag = "1")]
    value: f64,
    #[prost(int64, tag = "2")]
    timestamp: i64,
}

fn write_request(snapshot: StatsSnapshot) -> Result<WriteRequest, MetricsPushError> {
    let mut timeseries = Vec::new();
    let node_labels = BTreeMap::from([("k8s_node_name", snapshot.node.name.clone())]);
    append_stats(
        &mut timeseries,
        "k8s_node",
        &node_labels,
        snapshot.node.cpu.as_ref(),
        snapshot.node.memory.as_ref(),
    )?;

    for pod in snapshot.pods {
        let pod_labels = pod_labels(&snapshot.node.name, &pod.reference);
        append_stats(
            &mut timeseries,
            "k8s_pod",
            &pod_labels,
            pod.cpu.as_ref(),
            pod.memory.as_ref(),
        )?;

        for container in pod.containers {
            let mut labels = pod_labels.clone();
            labels.insert("k8s_container_name", container.name);
            append_stats(
                &mut timeseries,
                "k8s_container",
                &labels,
                container.cpu.as_ref(),
                container.memory.as_ref(),
            )?;
        }
    }

    Ok(WriteRequest { timeseries })
}

fn pod_labels(node: &str, pod: &PodReference) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("k8s_namespace_name", pod.namespace.clone()),
        ("k8s_node_name", node.to_owned()),
        ("k8s_pod_name", pod.name.clone()),
        ("k8s_pod_uid", pod.uid.clone()),
    ])
}

fn append_stats(
    series: &mut Vec<TimeSeries>,
    prefix: &str,
    labels: &BTreeMap<&'static str, String>,
    cpu: Option<&CpuStats>,
    memory: Option<&MemoryStats>,
) -> Result<(), MetricsPushError> {
    if let Some(cpu) = cpu {
        append_optional(
            series,
            format!("{prefix}_cpu_usage_cores"),
            labels,
            cpu.observed_at,
            cpu.usage_nano_cores
                .map(|value| value as f64 / 1_000_000_000.0),
        )?;
        append_optional(
            series,
            format!("{prefix}_cpu_time_seconds_total"),
            labels,
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
                series,
                format!("{prefix}_memory_{suffix}"),
                labels,
                memory.observed_at,
                value.map(|value| value as f64),
            )?;
        }
    }
    Ok(())
}

fn append_optional(
    series: &mut Vec<TimeSeries>,
    name: String,
    labels: &BTreeMap<&'static str, String>,
    observed_at: SystemTime,
    value: Option<f64>,
) -> Result<(), MetricsPushError> {
    let Some(value) = value else {
        return Ok(());
    };
    let mut all_labels = labels
        .iter()
        .map(|(name, value)| Label {
            name: (*name).to_owned(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    all_labels.push(Label {
        name: "__name__".to_owned(),
        value: name,
    });
    all_labels.sort_by(|left, right| left.name.cmp(&right.name));

    series.push(TimeSeries {
        labels: all_labels,
        samples: vec![Sample {
            value,
            timestamp: unix_millis(observed_at)?,
        }],
    });
    Ok(())
}

fn unix_millis(time: SystemTime) -> Result<i64, MetricsPushError> {
    let millis = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| MetricsPushError::Rejected("measurement predates Unix epoch".to_owned()))?
        .as_millis();
    i64::try_from(millis)
        .map_err(|_| MetricsPushError::Rejected("measurement timestamp is too large".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{ContainerStats, NodeStats, PodStats};
    use std::time::Duration;

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn maps_present_measurements_to_sorted_remote_write_series() {
        let snapshot = StatsSnapshot {
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
        };

        let request = write_request(snapshot).unwrap();
        assert_eq!(request.timeseries.len(), 3);
        assert_eq!(request.timeseries[0].samples[0].value, 0.25);
        assert_eq!(request.timeseries[0].samples[0].timestamp, 10_000);
        for series in request.timeseries {
            assert!(
                series
                    .labels
                    .windows(2)
                    .all(|pair| pair[0].name < pair[1].name)
            );
        }
    }

    #[test]
    fn protobuf_round_trips_through_snappy_block_encoding() {
        let request = WriteRequest {
            timeseries: vec![TimeSeries {
                labels: vec![Label {
                    name: "__name__".to_owned(),
                    value: "probe_test".to_owned(),
                }],
                samples: vec![Sample {
                    value: 1.0,
                    timestamp: 10,
                }],
            }],
        };
        let compressed = snap::raw::Encoder::new()
            .compress_vec(&request.encode_to_vec())
            .unwrap();
        let decoded = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .unwrap();
        assert_eq!(WriteRequest::decode(decoded.as_slice()).unwrap(), request);
    }
}
