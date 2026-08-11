// SPDX-License-Identifier: GPL-3.0-or-later

//! Joins reconstructed writes to node-local Kubernetes identity snapshots.

use crate::pipeline::WriteOperation;
use std::{collections::HashMap, fmt, str::FromStr, sync::Arc};
use tokio::sync::watch;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ContainerId {
    pub runtime: String,
    pub id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidContainerId {
    MissingSeparator,
    UnsupportedRuntime(String),
    InvalidOpaqueId,
}

impl fmt::Display for InvalidContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSeparator => write!(f, "container ID is missing ://"),
            Self::UnsupportedRuntime(runtime) => {
                write!(f, "unsupported container runtime {runtime}")
            }
            Self::InvalidOpaqueId => write!(f, "container ID is not 64 lowercase hex characters"),
        }
    }
}

impl std::error::Error for InvalidContainerId {}

impl FromStr for ContainerId {
    type Err = InvalidContainerId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (runtime, id) = value
            .split_once("://")
            .ok_or(InvalidContainerId::MissingSeparator)?;
        if runtime != "containerd" && runtime != "cri-o" {
            return Err(InvalidContainerId::UnsupportedRuntime(runtime.to_owned()));
        }
        if id.len() != 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(InvalidContainerId::InvalidOpaqueId);
        }
        Ok(Self {
            runtime: runtime.to_owned(),
            id: id.to_owned(),
        })
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.runtime, self.id)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct WorkloadIdentity {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub enum WorkloadResolution {
    Resolved(WorkloadIdentity),
    #[default]
    NoController,
    UnresolvedReplicaSet(WorkloadIdentity),
    UnsupportedOwner(WorkloadIdentity),
}

impl WorkloadResolution {
    pub fn resolved(&self) -> Option<&WorkloadIdentity> {
        match self {
            Self::Resolved(workload) => Some(workload),
            Self::NoController | Self::UnresolvedReplicaSet(_) | Self::UnsupportedOwner(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesIdentity {
    pub node: String,
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub container_name: String,
    pub container_id: ContainerId,
    pub workload: WorkloadResolution,
}

#[derive(Clone, Debug, Default)]
pub struct PodSnapshot {
    pub identities: HashMap<ContainerId, Vec<KubernetesIdentity>>,
    pub ready: bool,
    pub stale: bool,
    pub over_capacity: bool,
}

#[derive(Clone, Debug, Default)]
pub struct CgroupSnapshot {
    pub containers: HashMap<u64, Vec<ContainerId>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Enrichment {
    Enriched(KubernetesIdentity),
    Stale(KubernetesIdentity),
    UnresolvedCgroup,
    UnresolvedContainer(ContainerId),
    AmbiguousCgroup,
    AmbiguousContainer(ContainerId),
}

impl Enrichment {
    pub fn description(&self) -> String {
        match self {
            Self::Enriched(identity) => format!(
                "k8s={}/{}/{} pod_uid={} node={} container_id={} workload={}",
                identity.namespace,
                identity.pod_name,
                identity.container_name,
                identity.pod_uid,
                identity.node,
                identity.container_id,
                workload_description(identity),
            ),
            Self::Stale(identity) => format!(
                "k8s={}/{}/{} pod_uid={} node={} container_id={} workload={} metadata=stale",
                identity.namespace,
                identity.pod_name,
                identity.container_name,
                identity.pod_uid,
                identity.node,
                identity.container_id,
                workload_description(identity),
            ),
            Self::UnresolvedCgroup => "k8s=unresolved reason=cgroup-not-indexed".to_owned(),
            Self::UnresolvedContainer(id) => {
                format!("k8s=unresolved reason=container-not-in-pod-cache container_id={id}")
            }
            Self::AmbiguousCgroup => {
                "k8s=ambiguous reason=cgroup-has-multiple-containers".to_owned()
            }
            Self::AmbiguousContainer(id) => {
                format!("k8s=ambiguous reason=container-has-multiple-pods container_id={id}")
            }
        }
    }
}

fn workload_description(identity: &KubernetesIdentity) -> String {
    match &identity.workload {
        WorkloadResolution::Resolved(workload) => format!(
            "{}/{}/{}:{}",
            workload.api_version, workload.kind, workload.name, workload.uid
        ),
        WorkloadResolution::NoController => format!("standalone-pod:{}", identity.pod_uid),
        WorkloadResolution::UnresolvedReplicaSet(owner) => {
            format!("unresolved-replicaset:{}", owner.uid)
        }
        WorkloadResolution::UnsupportedOwner(owner) => {
            format!(
                "unsupported:{}/{}:{}",
                owner.api_version, owner.kind, owner.uid
            )
        }
    }
}

pub struct Enricher {
    pub cgroups: watch::Receiver<Arc<CgroupSnapshot>>,
    pub pods: watch::Receiver<Arc<PodSnapshot>>,
}

impl Enricher {
    pub fn enrich(&self, operation: &WriteOperation) -> Enrichment {
        let cgroups = self.cgroups.borrow();

        // Find the container(s) for the cgroup ID of the operation
        let Some(containers) = cgroups.containers.get(&operation.cgroup_id) else {
            return Enrichment::UnresolvedCgroup;
        };

        // If there are multiple containers for the cgroup ID, we cannot determine which one is correct
        // If there is exactly one container, we can look up the pod identity for that container
        let [container] = containers.as_slice() else {
            return Enrichment::AmbiguousCgroup;
        };

        // Look up the pod identity for the container
        let pods = self.pods.borrow();
        let Some(identities) = pods.identities.get(container) else {
            return Enrichment::UnresolvedContainer(container.clone());
        };

        let [identity] = identities.as_slice() else {
            return Enrichment::AmbiguousContainer(container.clone());
        };

        if pods.stale {
            return Enrichment::Stale(identity.clone());
        }

        Enrichment::Enriched(identity.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring_logtail_common::{CAPTURE_SOURCE_APPLICATION_SYSCALL, OPERATION_WRITE};

    const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn normalizes_only_complete_containerd_ids() {
        let id: ContainerId = format!("containerd://{ID}").parse().unwrap();
        assert_eq!(id.runtime, "containerd");
        assert_eq!(id.id, ID);
        assert!("docker://abc".parse::<ContainerId>().is_err());
        assert!("containerd://abc".parse::<ContainerId>().is_err());
    }

    #[test]
    fn description_is_clear_when_metadata_is_missing() {
        assert_eq!(
            Enrichment::UnresolvedCgroup.description(),
            "k8s=unresolved reason=cgroup-not-indexed"
        );
    }

    fn operation(cgroup_id: u64) -> WriteOperation {
        WriteOperation {
            capture_source: CAPTURE_SOURCE_APPLICATION_SYSCALL,
            operation_kind: OPERATION_WRITE,
            timestamp_ns: 1,
            cgroup_id,
            operation_id: 2,
            source_id: 0,
            result: Some(3),
            pid: 4,
            tid: 5,
            fd: Some(1),
            requested_len: 3,
            truncated: false,
            read_failed: false,
            capture_gaps: Vec::new(),
            bytes: b"hi\n".to_vec(),
        }
    }

    #[test]
    fn joins_exact_identity_and_reports_every_missing_boundary() {
        let container: ContainerId = format!("containerd://{ID}").parse().unwrap();
        let identity = KubernetesIdentity {
            node: "worker-1".into(),
            namespace: "payments".into(),
            pod_name: "checkout-abc".into(),
            pod_uid: "pod-uid".into(),
            container_name: "checkout".into(),
            container_id: container.clone(),
            workload: WorkloadResolution::NoController,
        };
        let (cgroup_sender, cgroup_receiver) = watch::channel(Arc::new(CgroupSnapshot::default()));
        let (pod_sender, pod_receiver) = watch::channel(Arc::new(PodSnapshot::default()));
        let enricher = Enricher {
            cgroups: cgroup_receiver,
            pods: pod_receiver,
        };

        assert_eq!(
            enricher.enrich(&operation(456)),
            Enrichment::UnresolvedCgroup
        );
        cgroup_sender.send_replace(Arc::new(CgroupSnapshot {
            containers: HashMap::from([(456, vec![container.clone()])]),
        }));
        assert_eq!(
            enricher.enrich(&operation(456)),
            Enrichment::UnresolvedContainer(container.clone())
        );
        pod_sender.send_replace(Arc::new(PodSnapshot {
            identities: HashMap::from([(container, vec![identity.clone()])]),
            stale: false,
            ..Default::default()
        }));
        assert_eq!(
            enricher.enrich(&operation(456)),
            Enrichment::Enriched(identity)
        );
    }

    #[test]
    fn reports_stale_and_ambiguous_snapshots() {
        let container: ContainerId = format!("containerd://{ID}").parse().unwrap();
        let identity = KubernetesIdentity {
            node: "worker-1".into(),
            namespace: "payments".into(),
            pod_name: "checkout".into(),
            pod_uid: "pod-uid".into(),
            container_name: "checkout".into(),
            container_id: container.clone(),
            workload: WorkloadResolution::NoController,
        };
        let (_, cgroups) = watch::channel(Arc::new(CgroupSnapshot {
            containers: HashMap::from([(456, vec![container.clone()])]),
        }));
        let (pods_sender, pods) = watch::channel(Arc::new(PodSnapshot {
            identities: HashMap::from([(container.clone(), vec![identity.clone()])]),
            stale: true,
            ..Default::default()
        }));
        let enricher = Enricher { cgroups, pods };

        assert_eq!(
            enricher.enrich(&operation(456)),
            Enrichment::Stale(identity.clone())
        );
        pods_sender.send_replace(Arc::new(PodSnapshot {
            identities: HashMap::from([(container.clone(), vec![identity.clone(), identity])]),
            stale: false,
            ..Default::default()
        }));
        assert_eq!(
            enricher.enrich(&operation(456)),
            Enrichment::AmbiguousContainer(container)
        );
    }
}
