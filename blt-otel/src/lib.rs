// SPDX-License-Identifier: GPL-3.0-or-later

//! The explicit boundary between BLT's loss-aware records and OTLP Logs.
//!
//! Plain version: [`blt_model::LogRecord`] describes what the node agent
//! captured. OTLP describes how that fact travels to the collector. This crate
//! performs that translation without teaching the model about protobuf or
//! silently reinterpreting kernel monotonic timestamps as wall-clock time.

use std::{collections::HashMap, fmt, sync::Arc};

use blt_model::{
    ContainerId, Enrichment, KubernetesIdentity, LogRecord as BltLogRecord, RecordIntegrity,
    Severity, StreamFileDescriptor, WorkloadIdentity, WorkloadResolution,
};
use opentelemetry_proto::tonic::{
    collector::logs::v1::ExportLogsServiceRequest,
    common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs, SeverityNumber},
    resource::v1::Resource,
};
use prost::Message as _;

mod exporter;

pub use exporter::{ExportConfig, ExportStats, OtlpExporter, OtlpSender, TryExportError};

/// Version of the BLT-specific OTLP attribute mapping.
///
/// OTLP itself is versioned upstream. This number covers meanings BLT owns,
/// such as integrity and workload-resolution attributes.

pub const BLT_OTLP_MAPPING_VERSION: i64 = 1;

/// Agent facts that apply to every record in one exported request.
#[derive(Clone, Debug, Eq, PartialEq)]

pub struct ExportContext {
    pub cluster_uid: Option<String>,
    pub agent_instance: String,
    pub agent_version: String,
}

/// Convert one finalized record to a complete OTLP Logs export request.
///
/// Batch grouping comes later. Returning the real request type now makes the
/// mapping fixture usable by both the future exporter and receiver.

pub fn export_request(record: &BltLogRecord, context: &ExportContext) -> ExportLogsServiceRequest {
    let resource = Resource {
        attributes: resource_attributes(record, context),
        dropped_attributes_count: 0,
        entity_refs: Vec::new(),
    };

    let scope = InstrumentationScope {
        name: "boring-logtail".to_owned(),
        version: context.agent_version.clone(),
        attributes: Vec::new(),
        dropped_attributes_count: 0,
    };

    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(resource),
            scope_logs: vec![ScopeLogs {
                scope: Some(scope),
                log_records: vec![log_record(record)],
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    }
}

/// Exact protobuf size used by future byte-bounded batches.

pub fn encoded_len(request: &ExportLogsServiceRequest) -> usize {
    request.encoded_len()
}

/// Why an OTLP record cannot be admitted as an exact BLT record.
#[derive(Clone, Debug, Eq, PartialEq)]

pub enum DecodeError {
    MissingResource,
    MissingAttribute(&'static str),
    InvalidAttribute(&'static str),
    UnsupportedMapping(i64),
    MissingObservedTime,
    InvalidObservedTime,
    MissingBody,
    UnsupportedBody,
    UnsupportedEnrichment,
    InvalidContainerId,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid BLT OTLP record: {self:?}")
    }
}

impl std::error::Error for DecodeError {}

/// Decode one OTLP record using its enclosing resource.
///
/// Generic OTLP records are not silently treated as BLT records. Required
/// mapping and identity attributes make admission explicit and versioned.

pub fn decode_record(resource: &Resource, log: &LogRecord) -> Result<BltLogRecord, DecodeError> {
    let resource = Attributes::new(&resource.attributes);
    let attributes = Attributes::new(&log.attributes);
    let mapping = attributes.integer("blt.mapping.version")?;

    if mapping != BLT_OTLP_MAPPING_VERSION {
        return Err(DecodeError::UnsupportedMapping(mapping));
    }

    if log.observed_time_unix_nano == 0 {
        return Err(DecodeError::MissingObservedTime);
    }

    let observed_at = jiff::Timestamp::from_nanosecond(i128::from(log.observed_time_unix_nano))
        .map_err(|_| DecodeError::InvalidObservedTime)?;

    let bytes: Arc<[u8]> = match log.body.as_ref().and_then(|body| body.value.as_ref()) {
        Some(any_value::Value::StringValue(text)) => Arc::from(text.as_bytes()),
        Some(any_value::Value::BytesValue(bytes)) => Arc::from(bytes.as_slice()),
        Some(_) => return Err(DecodeError::UnsupportedBody),
        None => return Err(DecodeError::MissingBody),
    };

    let enrichment = decode_enrichment(&resource, &attributes)?;

    Ok(BltLogRecord {
        observed_at,
        sampling_seed: attributes.unsigned("blt.sampling.seed")?,
        stream: decode_stream(attributes.text("blt.stream")?)?,
        enrichment,
        first_timestamp_ns: attributes.unsigned("blt.capture.first_timestamp_ns")?,
        last_timestamp_ns: attributes.unsigned("blt.capture.last_timestamp_ns")?,
        first_operation_id: attributes.unsigned("blt.capture.first_operation_id")?,
        last_operation_id: attributes.unsigned("blt.capture.last_operation_id")?,
        bytes,
        integrity: RecordIntegrity {
            capture_truncated: attributes.boolean("blt.integrity.capture_truncated")?,
            payload_read_failed: attributes.boolean("blt.integrity.payload_read_failed")?,
            max_size_split: attributes.boolean("blt.integrity.max_size_split")?,
            capacity_split: attributes.boolean("blt.integrity.capacity_split")?,
            capture_gap: attributes.boolean("blt.integrity.capture_gap")?,
            unterminated: attributes.boolean("blt.integrity.unterminated")?,
        },
        sample_percent: u8::try_from(attributes.integer("blt.sampling.percent")?)
            .map_err(|_| DecodeError::InvalidAttribute("blt.sampling.percent"))?,
        severity: decode_severity(log.severity_number),
    })
}

fn decode_enrichment(
    resource: &Attributes<'_>,
    attributes: &Attributes<'_>,
) -> Result<Enrichment, DecodeError> {
    let state = attributes.text("blt.enrichment.state")?;

    let unresolved_container = || {
        format!(
            "{}://{}",
            attributes.text("blt.enrichment.container.runtime")?,
            attributes.text("blt.enrichment.container.id")?
        )
        .parse::<ContainerId>()
        .map_err(|_| DecodeError::InvalidContainerId)
    };

    match state {
        "unresolved-cgroup" => return Ok(Enrichment::UnresolvedCgroup),
        "ambiguous-cgroup" => return Ok(Enrichment::AmbiguousCgroup),
        "unresolved-container" => {
            return unresolved_container().map(Enrichment::UnresolvedContainer);
        }
        "ambiguous-container" => {
            return unresolved_container().map(Enrichment::AmbiguousContainer);
        }
        "enriched" | "stale" => {}
        _ => return Err(DecodeError::UnsupportedEnrichment),
    }

    let container_id = format!(
        "{}://{}",
        resource.text("blt.container.runtime")?,
        resource.text("container.id")?
    )
    .parse::<ContainerId>()
    .map_err(|_| DecodeError::InvalidContainerId)?;

    let pod_uid = resource.text("k8s.pod.uid")?.to_owned();

    let workload = match attributes.optional_text("blt.k8s.workload.resolution")? {
        Some("pod") => WorkloadResolution::NoController,
        Some("resolved") => WorkloadResolution::Resolved(decode_workload(attributes)?),
        Some("unresolved-replicaset") => {
            WorkloadResolution::UnresolvedReplicaSet(decode_workload(attributes)?)
        }
        Some("unsupported-owner") => {
            WorkloadResolution::UnsupportedOwner(decode_workload(attributes)?)
        }
        _ => return Err(DecodeError::InvalidAttribute("blt.k8s.workload.resolution")),
    };

    let identity = KubernetesIdentity {
        node: resource.text("k8s.node.name")?.to_owned(),
        namespace: resource.text("k8s.namespace.name")?.to_owned(),
        pod_name: resource.text("k8s.pod.name")?.to_owned(),
        pod_uid,
        container_name: resource.text("k8s.container.name")?.to_owned(),
        container_id,
        workload,
    };

    Ok(if state == "stale" {
        Enrichment::Stale(identity)
    } else {
        Enrichment::Enriched(identity)
    })
}

fn decode_workload(attributes: &Attributes<'_>) -> Result<WorkloadIdentity, DecodeError> {
    Ok(WorkloadIdentity {
        api_version: attributes.text("blt.k8s.workload.api_version")?.to_owned(),
        kind: attributes.text("blt.k8s.workload.kind")?.to_owned(),
        name: attributes.text("blt.k8s.workload.name")?.to_owned(),
        uid: attributes.text("blt.k8s.workload.uid")?.to_owned(),
    })
}

fn decode_stream(value: &str) -> Result<StreamFileDescriptor, DecodeError> {
    match value {
        "stdout-candidate" => Ok(StreamFileDescriptor::Stdout),
        "stderr-candidate" => Ok(StreamFileDescriptor::Stderr),
        "unknown-candidate" => Ok(StreamFileDescriptor::Unknown),
        value if value.starts_with("fd-") => value[3..]
            .parse()
            .map(StreamFileDescriptor::Other)
            .map_err(|_| DecodeError::InvalidAttribute("blt.stream")),
        _ => Err(DecodeError::InvalidAttribute("blt.stream")),
    }
}

fn decode_severity(value: i32) -> Severity {
    match value {
        9..=12 => Severity::Info,
        13..=16 => Severity::Warn,
        17..=24 => Severity::Error,
        _ => Severity::Unknown,
    }
}

struct Attributes<'a>(HashMap<&'a str, &'a any_value::Value>);

impl<'a> Attributes<'a> {
    fn new(values: &'a [KeyValue]) -> Self {
        Self(
            values
                .iter()
                .filter_map(|item| Some((item.key.as_str(), item.value.as_ref()?.value.as_ref()?)))
                .collect(),
        )
    }

    fn value(&self, key: &'static str) -> Result<&any_value::Value, DecodeError> {
        self.0
            .get(key)
            .copied()
            .ok_or(DecodeError::MissingAttribute(key))
    }

    fn text(&self, key: &'static str) -> Result<&str, DecodeError> {
        match self.value(key)? {
            any_value::Value::StringValue(value) => Ok(value),
            _ => Err(DecodeError::InvalidAttribute(key)),
        }
    }

    fn optional_text(&self, key: &'static str) -> Result<Option<&str>, DecodeError> {
        match self.0.get(key).copied() {
            Some(any_value::Value::StringValue(value)) => Ok(Some(value)),
            Some(_) => Err(DecodeError::InvalidAttribute(key)),
            None => Ok(None),
        }
    }

    fn integer(&self, key: &'static str) -> Result<i64, DecodeError> {
        match self.value(key)? {
            any_value::Value::IntValue(value) => Ok(*value),
            _ => Err(DecodeError::InvalidAttribute(key)),
        }
    }

    fn unsigned(&self, key: &'static str) -> Result<u64, DecodeError> {
        Ok(u64::from_ne_bytes(self.integer(key)?.to_ne_bytes()))
    }

    fn boolean(&self, key: &'static str) -> Result<bool, DecodeError> {
        match self.value(key)? {
            any_value::Value::BoolValue(value) => Ok(*value),
            _ => Err(DecodeError::InvalidAttribute(key)),
        }
    }
}

fn resource_attributes(record: &BltLogRecord, context: &ExportContext) -> Vec<KeyValue> {
    let mut attributes = vec![
        string("blt.agent.instance", &context.agent_instance),
        string("blt.agent.version", &context.agent_version),
    ];

    if let Some(cluster_uid) = &context.cluster_uid {
        attributes.push(string("k8s.cluster.uid", cluster_uid));
    }

    if let Enrichment::Enriched(identity) | Enrichment::Stale(identity) = record.enrichment() {
        add_kubernetes_resource(&mut attributes, identity);
    }

    attributes
}

fn add_kubernetes_resource(attributes: &mut Vec<KeyValue>, identity: &KubernetesIdentity) {
    attributes.extend([
        string("k8s.node.name", &identity.node),
        string("k8s.namespace.name", &identity.namespace),
        string("k8s.pod.name", &identity.pod_name),
        string("k8s.pod.uid", &identity.pod_uid),
        string("k8s.container.name", &identity.container_name),
        string("container.id", &identity.container_id.id),
        string("blt.container.runtime", &identity.container_id.runtime),
    ]);

    match &identity.workload {
        WorkloadResolution::Resolved(workload) => {
            let semantic_key = match workload.kind.as_str() {
                "Deployment" => Some("k8s.deployment.name"),
                "ReplicaSet" => Some("k8s.replicaset.name"),
                "StatefulSet" => Some("k8s.statefulset.name"),
                "DaemonSet" => Some("k8s.daemonset.name"),
                "Job" => Some("k8s.job.name"),
                "CronJob" => Some("k8s.cronjob.name"),
                _ => None,
            };

            if let Some(key) = semantic_key {
                attributes.push(string(key, &workload.name));
            }
        }
        WorkloadResolution::NoController
        | WorkloadResolution::UnresolvedReplicaSet(_)
        | WorkloadResolution::UnsupportedOwner(_) => {}
    }
}

fn log_record(record: &BltLogRecord) -> LogRecord {
    let observed_time_unix_nano = u64::try_from(record.observed_at().as_nanosecond())
        .expect("BLT observation timestamps are after the Unix epoch");

    let integrity = record.integrity();

    let mut attributes = vec![
        integer("blt.mapping.version", BLT_OTLP_MAPPING_VERSION),
        integer_u64("blt.sampling.seed", record.sampling_seed()),
        integer("blt.sampling.percent", i64::from(record.sample_percent())),
        string("blt.stream", &record.stream().to_string()),
        integer_u64(
            "blt.capture.first_timestamp_ns",
            record.first_timestamp_ns(),
        ),
        integer_u64("blt.capture.last_timestamp_ns", record.last_timestamp_ns()),
        integer_u64(
            "blt.capture.first_operation_id",
            record.first_operation_id(),
        ),
        integer_u64("blt.capture.last_operation_id", record.last_operation_id()),
        boolean(
            "blt.integrity.capture_truncated",
            integrity.capture_truncated,
        ),
        boolean(
            "blt.integrity.payload_read_failed",
            integrity.payload_read_failed,
        ),
        boolean("blt.integrity.max_size_split", integrity.max_size_split),
        boolean("blt.integrity.capacity_split", integrity.capacity_split),
        boolean("blt.integrity.capture_gap", integrity.capture_gap),
        boolean("blt.integrity.unterminated", integrity.unterminated),
    ];

    add_enrichment_attributes(&mut attributes, record.enrichment());

    let (severity_number, severity_text) = severity(record.severity());

    LogRecord {
        // The BPF timestamps are monotonic, not Unix time. Keep this empty until
        // a source timestamp is parsed with an explicit clock-domain contract.
        time_unix_nano: 0,
        observed_time_unix_nano,
        severity_number,
        severity_text,
        body: Some(body(record.bytes())),
        attributes,
        dropped_attributes_count: 0,
        flags: 0,
        trace_id: Vec::new(),
        span_id: Vec::new(),
        event_name: String::new(),
    }
}

fn add_enrichment_attributes(attributes: &mut Vec<KeyValue>, enrichment: &Enrichment) {
    let state = match enrichment {
        Enrichment::Enriched(_) => "enriched",
        Enrichment::Stale(_) => "stale",
        Enrichment::UnresolvedCgroup => "unresolved-cgroup",
        Enrichment::UnresolvedContainer(_) => "unresolved-container",
        Enrichment::AmbiguousCgroup => "ambiguous-cgroup",
        Enrichment::AmbiguousContainer(_) => "ambiguous-container",
    };

    attributes.push(string("blt.enrichment.state", state));

    if let Enrichment::UnresolvedContainer(container) | Enrichment::AmbiguousContainer(container) =
        enrichment
    {
        attributes.extend([
            string("blt.enrichment.container.runtime", &container.runtime),
            string("blt.enrichment.container.id", &container.id),
        ]);
    }

    if let Enrichment::Enriched(identity) | Enrichment::Stale(identity) = enrichment {
        match &identity.workload {
            WorkloadResolution::Resolved(workload) => {
                attributes.push(string("blt.k8s.workload.resolution", "resolved"));

                add_workload_attributes(attributes, workload);
            }
            WorkloadResolution::NoController => {
                attributes.push(string("blt.k8s.workload.resolution", "pod"));
            }
            WorkloadResolution::UnresolvedReplicaSet(workload) => {
                attributes.push(string(
                    "blt.k8s.workload.resolution",
                    "unresolved-replicaset",
                ));

                add_workload_attributes(attributes, workload);
            }
            WorkloadResolution::UnsupportedOwner(workload) => {
                attributes.push(string("blt.k8s.workload.resolution", "unsupported-owner"));

                add_workload_attributes(attributes, workload);
            }
        }
    }
}

fn add_workload_attributes(attributes: &mut Vec<KeyValue>, workload: &WorkloadIdentity) {
    attributes.extend([
        string("blt.k8s.workload.api_version", &workload.api_version),
        string("blt.k8s.workload.kind", &workload.kind),
        string("blt.k8s.workload.name", &workload.name),
        string("blt.k8s.workload.uid", &workload.uid),
    ]);
}

fn body(bytes: &[u8]) -> AnyValue {
    let value = match std::str::from_utf8(bytes) {
        Ok(text) => any_value::Value::StringValue(text.to_owned()),
        Err(_) => any_value::Value::BytesValue(bytes.to_vec()),
    };

    AnyValue { value: Some(value) }
}

fn severity(value: Severity) -> (i32, String) {
    match value {
        Severity::Unknown => (SeverityNumber::Unspecified as i32, String::new()),
        Severity::Info => (SeverityNumber::Info as i32, "info".to_owned()),
        Severity::Warn => (SeverityNumber::Warn as i32, "warn".to_owned()),
        Severity::Error => (SeverityNumber::Error as i32, "error".to_owned()),
    }
}

fn string(key: &str, value: &str) -> KeyValue {
    key_value(key, any_value::Value::StringValue(value.to_owned()))
}

fn boolean(key: &str, value: bool) -> KeyValue {
    key_value(key, any_value::Value::BoolValue(value))
}

fn integer(key: &str, value: i64) -> KeyValue {
    key_value(key, any_value::Value::IntValue(value))
}

fn integer_u64(key: &str, value: u64) -> KeyValue {
    // Operation IDs and monotonic timestamps are opaque unsigned facts. OTLP
    // attributes only offer i64, so preserve their bit pattern for round-trip.
    integer(key, i64::from_ne_bytes(value.to_ne_bytes()))
}

fn key_value(key: &str, value: any_value::Value) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(AnyValue { value: Some(value) }),
        key_strindex: 0,
    }
}

#[cfg(test)]

mod tests {

    use std::{collections::HashMap, sync::Arc};

    use blt_model::{ContainerId, RecordIntegrity, StreamFileDescriptor, WorkloadIdentity};

    use super::*;

    fn source() -> KubernetesIdentity {
        KubernetesIdentity {
            node: "worker-1".into(),
            namespace: "flux-system".into(),
            pod_name: "kustomize-controller-abc".into(),
            pod_uid: "pod-uid".into(),
            container_name: "manager".into(),
            container_id: ContainerId {
                runtime: "cri-o".into(),
                id: "a".repeat(64),
            },
            workload: WorkloadResolution::Resolved(WorkloadIdentity {
                api_version: "apps/v1".into(),
                kind: "Deployment".into(),
                name: "kustomize-controller".into(),
                uid: "deployment-uid".into(),
            }),
        }
    }

    fn record(bytes: &[u8]) -> BltLogRecord {
        BltLogRecord {
            observed_at: "2026-08-13T18:10:52.313Z".parse().unwrap(),
            sampling_seed: 7,
            stream: StreamFileDescriptor::Stderr,
            enrichment: Enrichment::Enriched(source()),
            first_timestamp_ns: 11,
            last_timestamp_ns: 12,
            first_operation_id: 13,
            last_operation_id: 14,
            bytes: Arc::from(bytes),
            integrity: RecordIntegrity {
                capture_gap: true,
                ..RecordIntegrity::default()
            },
            sample_percent: 100,
            severity: Severity::Error,
        }
    }

    fn context() -> ExportContext {
        ExportContext {
            cluster_uid: Some("cluster-uid".into()),
            agent_instance: "worker-1/boring-logtail-abc".into(),
            agent_version: "0.1.0".into(),
        }
    }

    fn parts(request: &ExportLogsServiceRequest) -> (&Resource, &LogRecord) {
        let resource_logs = &request.resource_logs[0];

        (
            resource_logs.resource.as_ref().unwrap(),
            &resource_logs.scope_logs[0].log_records[0],
        )
    }

    fn attrs(values: &[KeyValue]) -> HashMap<&str, &any_value::Value> {
        values
            .iter()
            .map(|item| {
                (
                    item.key.as_str(),
                    item.value.as_ref().unwrap().value.as_ref().unwrap(),
                )
            })
            .collect()
    }

    #[test]

    fn maps_exact_kubernetes_resource_and_loss_evidence() {
        let request = export_request(&record(b"hello\n"), &context());

        let (resource, log) = parts(&request);

        let resource = attrs(&resource.attributes);

        assert_eq!(
            resource["container.id"],
            &any_value::Value::StringValue("a".repeat(64))
        );

        assert_eq!(
            resource["k8s.deployment.name"],
            &any_value::Value::StringValue("kustomize-controller".into())
        );

        assert_eq!(log.time_unix_nano, 0);

        assert_eq!(log.observed_time_unix_nano, 1_786_644_652_313_000_000);

        let log_attrs = attrs(&log.attributes);

        assert_eq!(
            log_attrs["blt.integrity.capture_gap"],
            &any_value::Value::BoolValue(true)
        );

        assert_eq!(log.severity_number, SeverityNumber::Error as i32);
    }

    #[test]

    fn utf8_and_non_utf8_bodies_round_trip_without_json_quoting() {
        let json = b"{\"level\":\"error\"}\n";

        let request = export_request(&record(json), &context());

        let (_, log) = parts(&request);

        assert_eq!(
            log.body.as_ref().unwrap().value,
            Some(any_value::Value::StringValue(
                String::from_utf8(json.to_vec()).unwrap()
            ))
        );

        let raw = b"hello\xff\n";

        let request = export_request(&record(raw), &context());

        let (_, log) = parts(&request);

        assert_eq!(
            log.body.as_ref().unwrap().value,
            Some(any_value::Value::BytesValue(raw.to_vec()))
        );
    }

    #[test]

    fn reports_real_protobuf_size_for_batch_admission() {
        let request = export_request(&record(b"hello\n"), &context());

        assert_eq!(encoded_len(&request), request.encode_to_vec().len());

        assert!(encoded_len(&request) > 6);
    }

    #[test]

    fn collector_decodes_the_exact_internal_record() {
        let original = record(b"{\"level\":\"error\"}\n");

        let request = export_request(&original, &context());

        let (resource, log) = parts(&request);

        assert_eq!(decode_record(resource, log).unwrap(), original);
    }

    #[test]

    fn every_honest_identity_state_round_trips() {
        let container = ContainerId {
            runtime: "cri-o".into(),
            id: "b".repeat(64),
        };

        let workload = WorkloadIdentity {
            api_version: "apps/v1".into(),
            kind: "ReplicaSet".into(),
            name: "controller-rs".into(),
            uid: "rs-uid".into(),
        };

        let mut unresolved_workload = source();

        unresolved_workload.workload = WorkloadResolution::UnresolvedReplicaSet(workload.clone());

        let mut unsupported_workload = source();

        unsupported_workload.workload = WorkloadResolution::UnsupportedOwner(workload);

        for enrichment in [
            Enrichment::UnresolvedCgroup,
            Enrichment::AmbiguousCgroup,
            Enrichment::UnresolvedContainer(container.clone()),
            Enrichment::AmbiguousContainer(container),
            Enrichment::Enriched(unresolved_workload),
            Enrichment::Stale(unsupported_workload),
        ] {
            let mut original = record(b"identity\n");

            original.enrichment = enrichment;

            let request = export_request(&original, &context());

            let (resource, log) = parts(&request);

            assert_eq!(decode_record(resource, log).unwrap(), original);
        }
    }

    #[test]

    fn collector_rejects_unknown_mapping_versions() {
        let mut request = export_request(&record(b"hello\n"), &context());

        let resource = request.resource_logs[0].resource.as_ref().unwrap().clone();

        let log = &mut request.resource_logs[0].scope_logs[0].log_records[0];

        let version = log
            .attributes
            .iter_mut()
            .find(|attribute| attribute.key == "blt.mapping.version")
            .unwrap();

        version.value.as_mut().unwrap().value = Some(any_value::Value::IntValue(99));

        assert_eq!(
            decode_record(&resource, log),
            Err(DecodeError::UnsupportedMapping(99))
        );
    }
}
