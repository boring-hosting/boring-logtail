// SPDX-License-Identifier: GPL-3.0-or-later

//! Honest source identity, including the ways identity can remain unresolved.
//!
//! Plain version: a container ID can lead to a Pod, but caches can be missing,
//! stale, or ambiguous. Those are data states, not errors to hide. The model
//! keeps them representable so downstream code never has to invent identity.

use std::{fmt, str::FromStr};

/// Runtime-qualified container identity, such as `containerd://<64 hex>`.
///
/// The runtime prefix matters because opaque IDs from different runtimes are
/// not declared to share one namespace.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]

pub struct ContainerId {
    pub runtime: String,
    pub id: String,
}

/// Why a raw Kubernetes container ID was rejected.
#[derive(Clone, Debug, Eq, PartialEq)]

pub enum InvalidContainerId {
    MissingSeparator,
    UnsupportedRuntime(String),
    InvalidOpaqueId,
}

impl fmt::Display for InvalidContainerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSeparator => write!(formatter, "container ID is missing ://"),
            Self::UnsupportedRuntime(runtime) => {
                write!(formatter, "unsupported container runtime {runtime}")
            }
            Self::InvalidOpaqueId => {
                write!(formatter, "container ID is not 64 lowercase hex characters")
            }
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}://{}", self.runtime, self.id)
    }
}

/// Stable Kubernetes controller identity used to group historical Pod replicas.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]

pub struct WorkloadIdentity {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
}

/// Result of following a Pod's controller chain without guessing from names.
///
/// ReplicaSets need their owner object to resolve a Deployment. Missing and
/// unsupported links remain explicit because guessing would mix unrelated logs.
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

/// Exact display and ownership identity for one Kubernetes container.
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

/// Outcome of joining one captured cgroup to cached Kubernetes metadata.
///
/// `Stale` carries useful last-known identity while admitting the cache is not
/// current. Ambiguous variants deliberately carry no guessed winner.
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
    /// Renders a compact, truthful diagnostic description for humans.

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
        WorkloadResolution::Resolved(workload) => {
            format!(
                "{}/{}/{}:{}",
                workload.api_version, workload.kind, workload.name, workload.uid
            )
        }
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

#[cfg(test)]

mod tests {

    use super::*;

    const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]

    fn parses_only_supported_complete_container_ids() {
        let id: ContainerId = format!("containerd://{ID}").parse().unwrap();

        assert_eq!(id.to_string(), format!("containerd://{ID}"));

        assert!("docker://abc".parse::<ContainerId>().is_err());

        assert!("containerd://abc".parse::<ContainerId>().is_err());
    }

    #[test]

    fn describes_unresolved_identity_honestly() {
        assert_eq!(
            Enrichment::UnresolvedCgroup.description(),
            "k8s=unresolved reason=cgroup-not-indexed"
        );
    }
}
