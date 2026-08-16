// SPDX-License-Identifier: GPL-3.0-or-later

//! Maintain node-local Kubernetes identity keyed by exact container ID.
//!
//! Pod status publishes the CRI container ID. Owner references provide the
//! workload, with one deliberate extra hop through a ReplicaSet to reach its
//! Deployment. Namespace watches merge into one immutable hot-path snapshot.

use std::{
    collections::{HashMap, HashSet},
    str::FromStr as _,
    sync::Arc,
};

use blt_model::{ContainerId, KubernetesIdentity, WorkloadIdentity, WorkloadResolution};
use futures::StreamExt as _;
use k8s_openapi::api::{
    apps::v1::ReplicaSet,
    core::v1::{ContainerStatus, Pod},
};
use kube::{
    Api, Client, ResourceExt,
    runtime::{WatchStreamExt as _, watcher},
};
use tokio::sync::{mpsc, watch};

use crate::enrichment::PodSnapshot;

pub const MAX_PODS_PER_NODE: usize = 16_384;

pub const MAX_REPLICA_SETS: usize = 16_384;

#[derive(Debug)]

enum WatchUpdate {
    PodEvent(usize, Box<watcher::Event<Pod>>),
    ReplicaSetEvent(usize, Box<watcher::Event<ReplicaSet>>),
    PodError(usize, String),
    ReplicaSetError(usize, String),
    PodStopped(usize),
    ReplicaSetStopped(usize),
}

struct WatchState<T> {
    known: HashMap<String, T>,
    relisting: Option<HashMap<String, T>>,
    ready: bool,
    stale: bool,
    over_capacity: bool,
    max_entries: usize,
}

impl<T> Default for WatchState<T> {
    fn default() -> Self {
        Self {
            known: HashMap::new(),
            relisting: None,
            ready: false,
            stale: false,
            over_capacity: false,
            max_entries: MAX_PODS_PER_NODE,
        }
    }
}

impl<T: ResourceExt> WatchState<T> {
    fn with_limit(max_entries: usize) -> Self {
        Self {
            max_entries,
            ..Self::default()
        }
    }

    fn apply(&mut self, object: T) {
        let key = object.uid().unwrap_or_else(|| object.name_any());

        let max_entries = self.max_entries;

        let target = if let Some(relisting) = &mut self.relisting {
            relisting
        } else {
            self.stale = false;

            &mut self.known
        };

        if target.contains_key(&key) || target.len() < max_entries {
            target.insert(key, object);
        } else {
            self.over_capacity = true;
        }
    }

    fn delete(&mut self, object: &T) {
        let key = object.uid().unwrap_or_else(|| object.name_any());

        if let Some(relisting) = &mut self.relisting {
            relisting.remove(&key);
        } else {
            self.known.remove(&key);

            self.stale = false;
        }
    }

    fn begin_relist(&mut self) {
        // Build fresh state beside the old map. Serving an empty half-built
        // relist would turn healthy identities into a wave of false misses.
        self.relisting = Some(HashMap::new());

        self.stale = true;

        self.over_capacity = false;
    }

    fn finish_relist(&mut self) {
        // InitDone makes the relist a complete point-in-time view. Until then,
        // `known` stays available but is explicitly stale.
        if let Some(fresh) = self.relisting.take() {
            self.known = fresh;
        }

        self.ready = true;

        self.stale = false;
    }
}

pub fn watcher_config(node: &str) -> watcher::Config {
    watcher::Config::default().fields(&format!("spec.nodeName={node}"))
}

pub fn snapshot_from_pods(node: &str, pods: impl IntoIterator<Item = Pod>) -> PodSnapshot {
    snapshot_from_resources(node, pods, std::iter::empty(), true, false)
}

fn snapshot_from_resources(
    node: &str,
    pods: impl IntoIterator<Item = Pod>,
    replica_sets: impl IntoIterator<Item = ReplicaSet>,
    ready: bool,
    stale: bool,
) -> PodSnapshot {
    snapshot_from_resources_with_history(
        node,
        pods,
        replica_sets,
        ready,
        stale,
        &mut HashMap::new(),
    )
}

fn snapshot_from_resources_with_history(
    node: &str,
    pods: impl IntoIterator<Item = Pod>,
    replica_sets: impl IntoIterator<Item = ReplicaSet>,
    ready: bool,
    stale: bool,
    last_workloads: &mut HashMap<String, WorkloadIdentity>,
) -> PodSnapshot {
    let pods = pods
        .into_iter()
        .take(MAX_PODS_PER_NODE + 1)
        .collect::<Vec<_>>();

    let replica_sets = replica_sets
        .into_iter()
        .take(MAX_REPLICA_SETS + 1)
        .collect::<Vec<_>>();

    let replica_set_count = replica_sets.len();

    let replica_sets = replica_sets
        .into_iter()
        .take(MAX_REPLICA_SETS)
        .filter_map(|replica_set| replica_set.uid().map(|uid| (uid, replica_set)))
        .collect::<HashMap<_, _>>();

    let mut snapshot = PodSnapshot {
        ready,
        stale,
        over_capacity: pods.len() > MAX_PODS_PER_NODE || replica_set_count > MAX_REPLICA_SETS,
        ..Default::default()
    };

    let mut current_pods = HashSet::new();

    for pod in pods.into_iter().take(MAX_PODS_PER_NODE) {
        let namespace = pod.namespace().unwrap_or_default();

        let pod_name = pod.name_any();

        let pod_uid = pod.metadata.uid.clone().unwrap_or_default();

        current_pods.insert(pod_uid.clone());

        let workload = match resolve_pod_workload(&pod, &replica_sets) {
            WorkloadResolution::Resolved(workload) => {
                last_workloads.insert(pod_uid.clone(), workload.clone());

                WorkloadResolution::Resolved(workload)
            }
            unresolved @ WorkloadResolution::UnresolvedReplicaSet(_) => {
                // Pod and ReplicaSet watches advance independently. During that
                // skew, keep the last proven parent and mark the snapshot stale.
                if let Some(workload) = last_workloads.get(&pod_uid) {
                    snapshot.stale = true;

                    WorkloadResolution::Resolved(workload.clone())
                } else {
                    unresolved
                }
            }
            resolution => resolution,
        };

        let Some(status) = pod.status else {
            continue;
        };

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
                &workload,
                container,
            );
        }
    }

    last_workloads.retain(|pod_uid, _| current_pods.contains(pod_uid));

    snapshot
}

#[cfg(test)]

fn merged_snapshot(
    node: &str,
    pod_states: &[WatchState<Pod>],
    replica_set_states: &[WatchState<ReplicaSet>],
) -> PodSnapshot {
    merged_snapshot_with_history(node, pod_states, replica_set_states, &mut HashMap::new())
}

fn merged_snapshot_with_history(
    node: &str,
    pod_states: &[WatchState<Pod>],
    replica_set_states: &[WatchState<ReplicaSet>],
    last_workloads: &mut HashMap<String, WorkloadIdentity>,
) -> PodSnapshot {
    let mut snapshot = snapshot_from_resources_with_history(
        node,
        pod_states
            .iter()
            .flat_map(|state| state.known.values().cloned()),
        replica_set_states
            .iter()
            .flat_map(|state| state.known.values().cloned()),
        pod_states.iter().all(|state| state.ready)
            && replica_set_states.iter().all(|state| state.ready),
        pod_states.iter().any(|state| state.stale)
            || replica_set_states.iter().any(|state| state.stale),
        last_workloads,
    );

    snapshot.over_capacity |= pod_states.iter().any(|state| state.over_capacity)
        || replica_set_states.iter().any(|state| state.over_capacity);

    snapshot
}

fn owner_identity(
    owner: &k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference,
) -> WorkloadIdentity {
    WorkloadIdentity {
        api_version: owner.api_version.clone(),
        kind: owner.kind.clone(),
        name: owner.name.clone(),
        uid: owner.uid.clone(),
    }
}

fn controller_owner<T: ResourceExt>(object: &T) -> Option<WorkloadIdentity> {
    object
        .meta()
        .owner_references
        .as_ref()?
        .iter()
        .find(|owner| owner.controller == Some(true))
        .map(owner_identity)
}

fn resolve_pod_workload(
    pod: &Pod,
    replica_sets: &HashMap<String, ReplicaSet>,
) -> WorkloadResolution {
    let Some(owner) = controller_owner(pod) else {
        return WorkloadResolution::NoController;
    };

    if owner.api_version != "apps/v1" || owner.kind != "ReplicaSet" {
        // Direct controllers already are the useful workload boundary. A
        // Deployment is special because Kubernetes inserts a ReplicaSet.
        return WorkloadResolution::Resolved(owner);
    }

    let Some(replica_set) = replica_sets.get(&owner.uid) else {
        return WorkloadResolution::UnresolvedReplicaSet(owner);
    };

    match controller_owner(replica_set) {
        None => WorkloadResolution::Resolved(owner),
        Some(parent) if parent.api_version == "apps/v1" && parent.kind == "Deployment" => {
            WorkloadResolution::Resolved(parent)
        }
        Some(parent) => WorkloadResolution::UnsupportedOwner(parent),
    }
}

fn insert_status(
    snapshot: &mut PodSnapshot,
    node: &str,
    namespace: &str,
    pod_name: &str,
    pod_uid: &str,
    workload: &WorkloadResolution,
    status: ContainerStatus,
) {
    let Some(raw_id) = status.container_id else {
        // A not-yet-started container has no CRI ID and cannot match a cgroup.
        // A later Pod status update will add it.
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
            workload: workload.clone(),
        });
}

pub async fn spawn_kubernetes_cache(
    node: String,
) -> anyhow::Result<watch::Receiver<Arc<PodSnapshot>>> {
    let client = Client::try_default().await?;

    // The node agent must enrich every local container. Namespace filtering is
    // collector policy; applying it here would discard data before policy can
    // be changed or replayed.
    let pod_apis = vec![Api::<Pod>::all(client.clone())];

    let replica_set_apis = vec![Api::<ReplicaSet>::all(client)];

    let count = pod_apis.len();

    let (updates, mut receiver_updates) = mpsc::channel(256);

    for (index, api) in pod_apis.into_iter().enumerate() {
        let sender = updates.clone();

        let config = watcher_config(&node);

        tokio::spawn(async move {
            let mut stream = watcher::watcher(api, config).default_backoff().boxed();

            while let Some(event) = stream.next().await {
                let update = match event {
                    Ok(event) => WatchUpdate::PodEvent(index, Box::new(event)),
                    Err(error) => WatchUpdate::PodError(index, error.to_string()),
                };

                if sender.send(update).await.is_err() {
                    return;
                }
            }

            let _ = sender.send(WatchUpdate::PodStopped(index)).await;
        });
    }

    for (index, api) in replica_set_apis.into_iter().enumerate() {
        let sender = updates.clone();

        tokio::spawn(async move {
            let mut stream = watcher::watcher(api, watcher::Config::default())
                .default_backoff()
                .boxed();

            while let Some(event) = stream.next().await {
                let update = match event {
                    Ok(event) => WatchUpdate::ReplicaSetEvent(index, Box::new(event)),
                    Err(error) => WatchUpdate::ReplicaSetError(index, error.to_string()),
                };

                if sender.send(update).await.is_err() {
                    return;
                }
            }

            let _ = sender.send(WatchUpdate::ReplicaSetStopped(index)).await;
        });
    }

    drop(updates);

    let initial = PodSnapshot {
        ready: count == 0,
        ..Default::default()
    };

    let (sender, receiver) = watch::channel(Arc::new(initial));

    tokio::spawn(async move {
        let mut pod_states = (0..count)
            .map(|index| WatchState::with_limit(partition_limit(MAX_PODS_PER_NODE, count, index)))
            .collect::<Vec<_>>();

        let mut replica_set_states = (0..count)
            .map(|index| WatchState::with_limit(partition_limit(MAX_REPLICA_SETS, count, index)))
            .collect::<Vec<_>>();

        let mut last_workloads = HashMap::new();

        while let Some(update) = receiver_updates.recv().await {
            let publish_snapshot = update_completes_snapshot(&update);

            match update {
                WatchUpdate::PodEvent(index, event) => match *event {
                    watcher::Event::Apply(pod) | watcher::Event::InitApply(pod) => {
                        pod_states[index].apply(pod);
                    }
                    watcher::Event::Delete(pod) => {
                        pod_states[index].delete(&pod);
                    }
                    watcher::Event::Init => {
                        pod_states[index].begin_relist();
                    }
                    watcher::Event::InitDone => {
                        pod_states[index].finish_relist();
                    }
                },
                WatchUpdate::ReplicaSetEvent(index, event) => match *event {
                    watcher::Event::Apply(rs) | watcher::Event::InitApply(rs) => {
                        replica_set_states[index].apply(rs)
                    }
                    watcher::Event::Delete(rs) => replica_set_states[index].delete(&rs),
                    watcher::Event::Init => replica_set_states[index].begin_relist(),
                    watcher::Event::InitDone => replica_set_states[index].finish_relist(),
                },
                WatchUpdate::PodError(index, error) => {
                    log::warn!("Kubernetes Pod watch error: {error}");

                    pod_states[index].stale = true;
                }
                WatchUpdate::ReplicaSetError(index, error) => {
                    log::warn!("Kubernetes ReplicaSet watch error: {error}");

                    replica_set_states[index].stale = true;
                }
                WatchUpdate::PodStopped(index) => {
                    log::warn!("Kubernetes Pod watch stopped");

                    pod_states[index].stale = true;
                }
                WatchUpdate::ReplicaSetStopped(index) => {
                    log::warn!("Kubernetes ReplicaSet watch stopped");

                    replica_set_states[index].stale = true;
                }
            }

            if publish_snapshot {
                sender.send_replace(Arc::new(merged_snapshot_with_history(
                    &node,
                    &pod_states,
                    &replica_set_states,
                    &mut last_workloads,
                )));
            }
        }
    });

    Ok(receiver)
}

fn update_completes_snapshot(update: &WatchUpdate) -> bool {
    match update {
        WatchUpdate::PodEvent(_, event) => !matches!(
            event.as_ref(),
            watcher::Event::Init | watcher::Event::InitApply(_)
        ),
        WatchUpdate::ReplicaSetEvent(_, event) => !matches!(
            event.as_ref(),
            watcher::Event::Init | watcher::Event::InitApply(_)
        ),
        WatchUpdate::PodError(..)
        | WatchUpdate::ReplicaSetError(..)
        | WatchUpdate::PodStopped(_)
        | WatchUpdate::ReplicaSetStopped(_) => true,
    }
}

fn partition_limit(total: usize, partitions: usize, index: usize) -> usize {
    // Divide one global bound among watches; N namespaces must not each receive
    // the entire allowance.
    if partitions == 0 {
        return 0;
    }

    total / partitions + usize::from(index < total % partitions)
}

#[cfg(test)]

mod tests {

    use serde_json::json;

    use super::*;

    #[test]
    fn initial_list_items_do_not_publish_partial_snapshots() {
        let pod = Box::new(watcher::Event::InitApply(Pod::default()));
        let replica_set = Box::new(watcher::Event::InitApply(ReplicaSet::default()));

        assert!(!update_completes_snapshot(&WatchUpdate::PodEvent(0, pod)));
        assert!(!update_completes_snapshot(&WatchUpdate::ReplicaSetEvent(
            0,
            replica_set
        )));
        assert!(update_completes_snapshot(&WatchUpdate::PodEvent(
            0,
            Box::new(watcher::Event::InitDone)
        )));
    }

    fn pod(namespace: &str, uid: &str, id: char) -> Pod {
        serde_json::from_value(json!({
        "metadata": {"name": "web", "namespace": namespace, "uid": uid},
        "spec": {"containers": [{"name": "web", "image": "web"}]},
        "status": {"containerStatuses": [{"name":"web","image":"web","imageID":"image","ready":true,"restartCount":0,"containerID":format!("containerd://{}", id.to_string().repeat(64))}]}
    })).unwrap()
    }

    fn owner(api_version: &str, kind: &str, name: &str, uid: &str) -> serde_json::Value {
        json!({
            "apiVersion": api_version, "kind": kind, "name": name, "uid": uid,
            "controller": true
        })
    }

    fn owned_pod(owner: serde_json::Value) -> Pod {
        let mut pod = pod("shop", "pod-uid", 'a');

        pod.metadata.owner_references = Some(vec![serde_json::from_value(owner).unwrap()]);

        pod
    }

    fn replica_set(uid: &str, owner: Option<serde_json::Value>) -> ReplicaSet {
        serde_json::from_value(json!({
            "apiVersion": "apps/v1", "kind": "ReplicaSet",
            "metadata": {"name": "web-rs", "namespace": "shop", "uid": uid,
                "ownerReferences": owner.into_iter().collect::<Vec<_>>()},
            "spec": {"selector": {"matchLabels": {"app": "web"}}}
        }))
        .unwrap()
    }

    fn workload(snapshot: &PodSnapshot) -> &WorkloadResolution {
        &snapshot.identities.values().next().unwrap()[0].workload
    }

    #[test]

    fn resolves_direct_controller_and_no_controller() {
        let direct = snapshot_from_resources(
            "node",
            [owned_pod(owner("batch/v1", "Job", "worker", "job-uid"))],
            [],
            true,
            false,
        );

        assert_eq!(workload(&direct).resolved().unwrap().uid, "job-uid");

        assert_eq!(
            workload(&snapshot_from_pods("node", [pod("shop", "pod", 'a')])),
            &WorkloadResolution::NoController
        );
    }

    #[test]

    fn resolves_replica_set_to_deployment_by_uid_only() {
        let pod = owned_pod(owner("apps/v1", "ReplicaSet", "web-rs", "wanted-uid"));

        let wrong = replica_set(
            "wrong-uid",
            Some(owner("apps/v1", "Deployment", "wrong", "wrong-deploy")),
        );

        let right = replica_set(
            "wanted-uid",
            Some(owner("apps/v1", "Deployment", "web", "deploy-uid")),
        );

        let snapshot = snapshot_from_resources("node", [pod], [wrong, right], true, false);

        let resolved = workload(&snapshot).resolved().unwrap();

        assert_eq!(
            (
                resolved.kind.as_str(),
                resolved.name.as_str(),
                resolved.uid.as_str()
            ),
            ("Deployment", "web", "deploy-uid")
        );
    }

    #[test]

    fn exposes_standalone_missing_and_unsupported_replica_set_chains() {
        let pod_owner = owner("apps/v1", "ReplicaSet", "web-rs", "rs-uid");

        let standalone = snapshot_from_resources(
            "node",
            [owned_pod(pod_owner.clone())],
            [replica_set("rs-uid", None)],
            true,
            false,
        );

        assert_eq!(workload(&standalone).resolved().unwrap().uid, "rs-uid");

        let missing =
            snapshot_from_resources("node", [owned_pod(pod_owner.clone())], [], true, false);

        assert!(
            matches!(workload(&missing), WorkloadResolution::UnresolvedReplicaSet(owner) if owner.uid == "rs-uid")
        );

        let unsupported = snapshot_from_resources(
            "node",
            [owned_pod(pod_owner)],
            [replica_set(
                "rs-uid",
                Some(owner("example/v1", "Rollout", "web", "rollout-uid")),
            )],
            true,
            false,
        );

        assert!(
            matches!(workload(&unsupported), WorkloadResolution::UnsupportedOwner(owner) if owner.uid == "rollout-uid")
        );
    }

    #[test]

    fn replica_set_loss_preserves_last_resolved_workload_as_stale() {
        let pod = owned_pod(owner("apps/v1", "ReplicaSet", "web-rs", "rs-uid"));

        let replica_set = replica_set(
            "rs-uid",
            Some(owner("apps/v1", "Deployment", "web", "deploy-uid")),
        );

        let mut history = HashMap::new();

        let fresh = snapshot_from_resources_with_history(
            "node",
            [pod.clone()],
            [replica_set],
            true,
            false,
            &mut history,
        );

        assert!(!fresh.stale);

        let after_delete =
            snapshot_from_resources_with_history("node", [pod], [], true, false, &mut history);

        assert!(after_delete.stale);

        assert_eq!(
            workload(&after_delete).resolved().unwrap().uid,
            "deploy-uid"
        );
    }

    #[test]

    fn missing_replica_set_uid_never_falls_back_to_name() {
        let snapshot = snapshot_from_resources(
            "node",
            [owned_pod(owner("apps/v1", "ReplicaSet", "web-rs", ""))],
            [replica_set("actual-uid", None)],
            true,
            false,
        );

        assert!(
            matches!(workload(&snapshot), WorkloadResolution::UnresolvedReplicaSet(owner) if owner.uid.is_empty())
        );
    }

    #[test]

    fn preserves_the_node_field_selector() {
        assert_eq!(
            watcher_config("worker-1").field_selector.as_deref(),
            Some("spec.nodeName=worker-1")
        );
    }

    #[test]

    fn indexes_regular_init_and_ephemeral_containers() {
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

    fn indexes_container_kinds_and_preserves_ambiguity() {
        let snapshot =
            snapshot_from_pods("worker", [pod("shop", "one", 'a'), pod("shop", "two", 'a')]);

        assert_eq!(snapshot.identities.len(), 1);

        assert_eq!(snapshot.identities.values().next().unwrap().len(), 2);

        assert!(snapshot.ready);
    }

    #[test]

    fn merged_state_has_global_readiness_staleness_and_deletion() {
        let mut states = vec![WatchState::default(), WatchState::default()];

        states[0].known.insert("one".into(), pod("one", "one", 'a'));

        states[0].ready = true;

        let mut replica_sets = vec![WatchState::<ReplicaSet>::default(), WatchState::default()];

        assert!(!merged_snapshot("node", &states, &replica_sets).ready);

        states[1].ready = true;

        states[1].stale = true;

        replica_sets[0].ready = true;

        replica_sets[1].ready = true;

        let snapshot = merged_snapshot("node", &states, &replica_sets);

        assert!(snapshot.ready && snapshot.stale);

        states[0].known.clear();

        assert!(
            merged_snapshot("node", &states, &replica_sets)
                .identities
                .is_empty()
        );
    }

    #[test]

    fn relist_keeps_last_known_snapshot_until_complete() {
        let mut state = WatchState::default();

        state.apply(pod("old", "old", 'a'));

        state.finish_relist();

        state.begin_relist();

        state.apply(pod("new", "new", 'b'));

        let replica_sets = [WatchState::<ReplicaSet> {
            ready: true,
            ..Default::default()
        }];

        let during = merged_snapshot("node", std::slice::from_ref(&state), &replica_sets);

        assert!(during.ready && during.stale);

        assert_eq!(
            during.identities.values().next().unwrap()[0].namespace,
            "old"
        );

        state.finish_relist();

        let after = merged_snapshot("node", &[state], &replica_sets);

        assert!(after.ready && !after.stale);

        assert_eq!(
            after.identities.values().next().unwrap()[0].namespace,
            "new"
        );
    }

    #[test]

    fn ordinary_apply_clears_stale_state() {
        let mut state = WatchState::default();

        state.begin_relist();

        state.apply(pod("shop", "old", 'a'));

        state.finish_relist();

        state.stale = true;

        state.apply(pod("shop", "new", 'b'));

        assert!(state.ready);

        assert!(!state.stale);

        assert_eq!(state.known.len(), 2);
    }

    #[test]

    fn one_global_pod_bound_is_reported() {
        let pods = (0..=MAX_PODS_PER_NODE).map(|n| pod("shop", &format!("p{n}"), 'a'));

        assert!(snapshot_from_pods("node", pods).over_capacity);
    }
}
