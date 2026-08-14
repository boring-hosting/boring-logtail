// SPDX-License-Identifier: GPL-3.0-or-later

//! Join reconstructed writes to node-local Kubernetes identity snapshots.
//!
//! The chain is exact and deliberately split in two:
//! `cgroup id -> container id -> Pod/container/workload`.
//! PID and TID identify a syscall while chunks are assembled, but Kubernetes
//! does not index Pods by host task ID. Container ID is the shared name known
//! to both cgroup layout and Kubernetes CRI status.

use std::{collections::HashMap, sync::Arc};

use blt_model::{ContainerId, Enrichment, KubernetesIdentity};
use tokio::sync::watch;

use crate::pipeline::WriteOperation;

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

pub struct Enricher {
    pub cgroups: watch::Receiver<Arc<CgroupSnapshot>>,
    pub pods: watch::Receiver<Arc<PodSnapshot>>,
}

impl Enricher {
    /// Perform snapshot-only identity lookup; no filesystem or network I/O is
    /// allowed on the record path.

    pub fn enrich(&self, operation: &WriteOperation) -> Enrichment {
        let cgroups = self.cgroups.borrow();

        // Vectors preserve ambiguity. Choosing the first duplicate would turn
        // uncertain evidence into confidently wrong attribution.
        let Some(containers) = cgroups.containers.get(&operation.cgroup_id) else {
            return Enrichment::UnresolvedCgroup;
        };

        let [container] = containers.as_slice() else {
            return Enrichment::AmbiguousCgroup;
        };

        let pods = self.pods.borrow();

        let Some(identities) = pods.identities.get(container) else {
            return Enrichment::UnresolvedContainer(container.clone());
        };

        let [identity] = identities.as_slice() else {
            return Enrichment::AmbiguousContainer(container.clone());
        };

        if pods.stale {
            // Known-but-old identity remains useful if uncertainty travels with
            // it all the way to storage and API consumers.
            return Enrichment::Stale(identity.clone());
        }

        Enrichment::Enriched(identity.clone())
    }
}

#[cfg(test)]

mod tests {

    use blt_abi::{CAPTURE_SOURCE_APPLICATION_SYSCALL, OPERATION_WRITE};
    use blt_model::WorkloadResolution;

    use super::*;

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
