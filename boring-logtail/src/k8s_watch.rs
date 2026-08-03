// SPDX-License-Identifier: GPL-3.0-or-later

//! One node-scoped Kubernetes Pod watch and exact-ID CRI merge.

use crate::{
    cri_metadata::{CriIdentity, CriSnapshot},
    enrichment::{ContainerId, KubernetesIdentity, PodSnapshot},
};
use futures::StreamExt as _;
use k8s_openapi::api::core::v1::{ContainerStatus, Pod};
use kube::{Api, Client, ResourceExt as _, runtime::watcher};
use std::{collections::HashMap, str::FromStr as _, sync::Arc};
use tokio::sync::watch;

pub const MAX_PODS_PER_NODE: usize = 16_384;

pub fn snapshot_from_pods(node: &str, pods: impl IntoIterator<Item = Pod>) -> PodSnapshot {
    let mut snapshot = PodSnapshot::default();
    for pod in pods.into_iter().take(MAX_PODS_PER_NODE) {
        let namespace = pod.namespace().unwrap_or_default();
        let pod_name = pod.name_any();
        let pod_uid = pod.metadata.uid.clone().unwrap_or_default();
        let Some(status) = pod.status else { continue };
        for container in status
            .container_statuses
            .into_iter()
            .flatten()
            .chain(status.init_container_statuses.into_iter().flatten())
            .chain(status.ephemeral_container_statuses.into_iter().flatten())
        {
            insert_status(
                &mut snapshot,
                node,
                &namespace,
                &pod_name,
                &pod_uid,
                container,
            );
        }
    }
    snapshot
}

fn insert_status(
    snapshot: &mut PodSnapshot,
    node: &str,
    namespace: &str,
    pod_name: &str,
    pod_uid: &str,
    status: ContainerStatus,
) {
    let Some(raw_id) = status.container_id else {
        return;
    };
    let Ok(container_id) = ContainerId::from_str(&raw_id) else {
        return;
    };
    snapshot
        .identities
        .entry(container_id.clone())
        .or_default()
        .push(KubernetesIdentity {
            node: node.to_owned(),
            namespace: namespace.to_owned(),
            pod_name: pod_name.to_owned(),
            pod_uid: pod_uid.to_owned(),
            container_name: status.name,
            container_id,
            restart_count: status.restart_count.max(0) as u32,
            tombstone: false,
        });
}

pub async fn spawn_kubernetes_cache(
    node: String,
) -> anyhow::Result<watch::Receiver<Arc<PodSnapshot>>> {
    let client = Client::try_default().await?;
    let pods = Api::<Pod>::all(client);
    let config = watcher::Config::default().fields(&format!("spec.nodeName={node}"));
    let (sender, receiver) = watch::channel(Arc::new(PodSnapshot::default()));
    tokio::spawn(async move {
        let mut known = HashMap::<String, Pod>::new();
        let mut stream = watcher::watcher(pods, config).boxed();
        while let Some(event) = stream.next().await {
            match event {
                Ok(watcher::Event::Apply(pod) | watcher::Event::InitApply(pod)) => {
                    known.insert(pod.uid().unwrap_or_else(|| pod.name_any()), pod);
                }
                Ok(watcher::Event::Delete(pod)) => {
                    known.remove(&pod.uid().unwrap_or_else(|| pod.name_any()));
                }
                Ok(watcher::Event::Init) => known.clear(),
                Ok(watcher::Event::InitDone) => {}
                Err(error) => {
                    log::warn!("Kubernetes Pod watch error: {error}");
                    let mut stale = snapshot_from_pods(&node, known.values().cloned());
                    stale.stale = true;
                    sender.send_replace(Arc::new(stale));
                    continue;
                }
            }
            sender.send_replace(Arc::new(snapshot_from_pods(&node, known.values().cloned())));
        }
        log::warn!("Kubernetes Pod watch stopped");
    });
    Ok(receiver)
}

pub fn merge_cri_and_kubernetes(
    node: &str,
    cri: &CriSnapshot,
    kubernetes: &PodSnapshot,
) -> PodSnapshot {
    let mut merged = PodSnapshot {
        stale: cri.stale && kubernetes.stale,
        ..PodSnapshot::default()
    };
    for identities in cri.identities.values() {
        for cri_identity in identities {
            let container_id = ContainerId {
                runtime: cri_identity.runtime.scheme().to_owned(),
                id: cri_identity.container_id.clone(),
            };
            match kubernetes.identities.get(&container_id) {
                Some(kubernetes_identities)
                    if kubernetes_identities
                        .iter()
                        .any(|identity| identities_agree(cri_identity, identity)) =>
                {
                    merged
                        .identities
                        .entry(container_id)
                        .or_default()
                        .extend(kubernetes_identities.iter().cloned());
                }
                Some(kubernetes_identities) => {
                    let entries = merged.identities.entry(container_id.clone()).or_default();
                    entries.push(from_cri(node, container_id, cri_identity));
                    entries.extend(kubernetes_identities.iter().cloned());
                }
                None => {
                    merged
                        .identities
                        .entry(container_id.clone())
                        .or_default()
                        .push(from_cri(node, container_id, cri_identity));
                }
            }
        }
    }
    for (container_id, identities) in &kubernetes.identities {
        merged
            .identities
            .entry(container_id.clone())
            .or_insert_with(|| identities.clone());
    }
    merged
}

pub fn spawn_merged_cache(
    node: String,
    mut cri: watch::Receiver<Arc<CriSnapshot>>,
    mut kubernetes: watch::Receiver<Arc<PodSnapshot>>,
) -> watch::Receiver<Arc<PodSnapshot>> {
    let initial = merge_cri_and_kubernetes(&node, &cri.borrow(), &kubernetes.borrow());
    let (sender, receiver) = watch::channel(Arc::new(initial));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = cri.changed() => if changed.is_err() { return; },
                changed = kubernetes.changed() => if changed.is_err() { return; },
            }
            sender.send_replace(Arc::new(merge_cri_and_kubernetes(
                &node,
                &cri.borrow(),
                &kubernetes.borrow(),
            )));
        }
    });
    receiver
}

fn identities_agree(cri: &CriIdentity, kubernetes: &KubernetesIdentity) -> bool {
    cri.namespace == kubernetes.namespace
        && cri.pod_name == kubernetes.pod_name
        && cri.pod_uid == kubernetes.pod_uid
        && cri.container_name == kubernetes.container_name
}

fn from_cri(node: &str, container_id: ContainerId, identity: &CriIdentity) -> KubernetesIdentity {
    KubernetesIdentity {
        node: node.to_owned(),
        namespace: identity.namespace.clone(),
        pod_name: identity.pod_name.clone(),
        pod_uid: identity.pod_uid.clone(),
        container_name: identity.container_name.clone(),
        container_id,
        restart_count: identity.attempt,
        tombstone: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cri_metadata::CriRuntime;

    fn cri() -> CriIdentity {
        CriIdentity {
            runtime: CriRuntime::Crio,
            container_id: "a".repeat(64),
            namespace: "shop".into(),
            pod_name: "web-0".into(),
            pod_uid: "uid".into(),
            container_name: "web".into(),
            attempt: 1,
        }
    }

    #[test]
    fn uses_cri_when_kubernetes_is_absent() {
        let cri_identity = cri();
        let cri = CriSnapshot {
            identities: HashMap::from([(cri_identity.container_id.clone(), vec![cri_identity])]),
            stale: false,
        };
        let merged = merge_cri_and_kubernetes("worker", &cri, &PodSnapshot::default());
        let id = ContainerId {
            runtime: "cri-o".into(),
            id: "a".repeat(64),
        };
        assert_eq!(merged.identities[&id][0].node, "worker");
    }

    #[test]
    fn preserves_conflict_as_ambiguity() {
        let cri_identity = cri();
        let id = ContainerId {
            runtime: "cri-o".into(),
            id: cri_identity.container_id.clone(),
        };
        let cri = CriSnapshot {
            identities: HashMap::from([(id.id.clone(), vec![cri_identity])]),
            stale: false,
        };
        let mut conflicting = from_cri("worker", id.clone(), &cri.identities[&id.id][0]);
        conflicting.pod_uid = "different".into();
        let kubernetes = PodSnapshot {
            identities: HashMap::from([(id.clone(), vec![conflicting])]),
            stale: false,
        };
        assert_eq!(
            merge_cri_and_kubernetes("worker", &cri, &kubernetes).identities[&id].len(),
            2
        );
    }
}
