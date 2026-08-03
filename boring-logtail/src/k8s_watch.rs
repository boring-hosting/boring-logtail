// SPDX-License-Identifier: GPL-3.0-or-later

//! One node-scoped Kubernetes Pod watch keyed by exact container ID.

use crate::enrichment::{ContainerId, KubernetesIdentity, PodSnapshot};
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn indexes_every_container_kind_by_exact_id() {
        let regular = "a".repeat(64);
        let init = "b".repeat(64);
        let ephemeral = "c".repeat(64);
        let pod: Pod = serde_json::from_value(json!({
            "metadata": {"name": "web-0", "namespace": "shop", "uid": "pod-uid"},
            "spec": {"containers": [{"name": "web", "image": "web"}]},
            "status": {
                "containerStatuses": [{
                    "name": "web", "image": "web", "imageID": "image", "ready": true,
                    "restartCount": 0, "containerID": format!("containerd://{regular}")
                }],
                "initContainerStatuses": [{
                    "name": "setup", "image": "setup", "imageID": "image", "ready": true,
                    "restartCount": 0, "containerID": format!("containerd://{init}")
                }],
                "ephemeralContainerStatuses": [{
                    "name": "debug", "image": "debug", "imageID": "image", "ready": true,
                    "restartCount": 0, "containerID": format!("containerd://{ephemeral}")
                }]
            }
        }))
        .unwrap();

        let snapshot = snapshot_from_pods("worker-1", [pod]);

        assert_eq!(snapshot.identities.len(), 3);
        for (id, name) in [(regular, "web"), (init, "setup"), (ephemeral, "debug")] {
            let id: ContainerId = format!("containerd://{id}").parse().unwrap();
            let identity = &snapshot.identities[&id][0];
            assert_eq!(identity.container_name, name);
            assert_eq!(identity.pod_uid, "pod-uid");
            assert_eq!(identity.node, "worker-1");
        }
    }

    #[test]
    fn rejects_malformed_ids_and_preserves_ambiguity() {
        let id = "d".repeat(64);
        let pods = ["uid-1", "uid-2"].map(|uid| {
            serde_json::from_value(json!({
                "metadata": {"name": "web", "namespace": "shop", "uid": uid},
                "spec": {"containers": [{"name": "web", "image": "web"}]},
                "status": {"containerStatuses": [
                    {"name": "broken", "image": "web", "imageID": "image", "ready": true,
                     "restartCount": 0, "containerID": "containerd://short"},
                    {"name": "web", "image": "web", "imageID": "image", "ready": true,
                     "restartCount": 0, "containerID": format!("containerd://{id}")}
                ]}
            }))
            .unwrap()
        });

        let snapshot = snapshot_from_pods("worker-1", pods);
        let id: ContainerId = format!("containerd://{id}").parse().unwrap();

        assert_eq!(snapshot.identities.len(), 1);
        assert_eq!(snapshot.identities[&id].len(), 2);
    }
}
