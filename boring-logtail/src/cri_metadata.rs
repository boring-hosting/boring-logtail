// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded, node-local CRI identity reconciliation.

use anyhow::{Context as _, bail};
use hyper_util::rt::TokioIo;
use k8s_cri::v1::{
    ListContainersRequest, ListPodSandboxRequest, runtime_service_client::RuntimeServiceClient,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{net::UnixStream, sync::watch};
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

pub const DEFAULT_CRI_RECONCILE_INTERVAL: Duration = Duration::from_secs(15);
pub const MAX_CRI_OBJECTS: usize = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CriRuntime {
    Crio,
    Containerd,
}

impl CriRuntime {
    pub fn scheme(self) -> &'static str {
        match self {
            Self::Crio => "cri-o",
            Self::Containerd => "containerd",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CriEndpoint {
    pub runtime: CriRuntime,
    pub socket: PathBuf,
}

impl CriEndpoint {
    pub fn configured(runtime: &str, socket: PathBuf) -> anyhow::Result<Self> {
        let runtime = match runtime {
            "cri-o" => CriRuntime::Crio,
            "containerd" => CriRuntime::Containerd,
            other => bail!("unsupported BORING_LOGTAIL_CRI_RUNTIME {other}"),
        };
        if !socket.is_absolute() {
            bail!("CRI socket path must be absolute: {}", socket.display());
        }
        Ok(Self { runtime, socket })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CriContainer {
    pub id: String,
    pub pod_sandbox_id: String,
    pub name: String,
    pub attempt: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CriSandbox {
    pub id: String,
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CriIdentity {
    pub runtime: CriRuntime,
    pub container_id: String,
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub container_name: String,
    pub attempt: u32,
}

#[derive(Clone, Debug, Default)]
pub struct CriSnapshot {
    pub identities: HashMap<String, Vec<CriIdentity>>,
    pub stale: bool,
}

pub fn build_snapshot(
    runtime: CriRuntime,
    containers: impl IntoIterator<Item = CriContainer>,
    sandboxes: impl IntoIterator<Item = CriSandbox>,
) -> anyhow::Result<CriSnapshot> {
    let sandboxes = sandboxes
        .into_iter()
        .take(MAX_CRI_OBJECTS + 1)
        .collect::<Vec<_>>();
    let containers = containers
        .into_iter()
        .take(MAX_CRI_OBJECTS + 1)
        .collect::<Vec<_>>();
    if sandboxes.len() > MAX_CRI_OBJECTS || containers.len() > MAX_CRI_OBJECTS {
        bail!("CRI response exceeds {MAX_CRI_OBJECTS} objects");
    }
    let by_sandbox = sandboxes
        .into_iter()
        .map(|item| (item.id.clone(), item))
        .collect::<HashMap<_, _>>();
    let mut snapshot = CriSnapshot::default();
    for container in containers {
        if container.id.is_empty() || container.pod_sandbox_id.is_empty() {
            continue;
        }
        let Some(sandbox) = by_sandbox.get(&container.pod_sandbox_id) else {
            continue;
        };
        snapshot
            .identities
            .entry(container.id.clone())
            .or_default()
            .push(CriIdentity {
                runtime,
                container_id: container.id,
                namespace: sandbox.namespace.clone(),
                pod_name: sandbox.pod_name.clone(),
                pod_uid: sandbox.pod_uid.clone(),
                container_name: container.name,
                attempt: container.attempt,
            });
    }
    Ok(snapshot)
}

#[derive(Debug, Default)]
pub struct CriCounters {
    pub attempts: AtomicU64,
    pub successes: AtomicU64,
    pub failures: AtomicU64,
    pub containers: AtomicU64,
}

pub fn spawn_cri_cache(
    endpoint: CriEndpoint,
    interval: Duration,
) -> (watch::Receiver<Arc<CriSnapshot>>, Arc<CriCounters>) {
    let (sender, receiver) = watch::channel(Arc::new(CriSnapshot::default()));
    let counters = Arc::new(CriCounters::default());
    let task_counters = Arc::clone(&counters);
    tokio::spawn(async move {
        let mut delay = Duration::ZERO;
        loop {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            task_counters.attempts.fetch_add(1, Ordering::Relaxed);
            match reconcile(&endpoint).await {
                Ok(snapshot) => {
                    task_counters.successes.fetch_add(1, Ordering::Relaxed);
                    task_counters.containers.store(
                        snapshot.identities.values().map(Vec::len).sum::<usize>() as u64,
                        Ordering::Relaxed,
                    );
                    sender.send_replace(Arc::new(snapshot));
                    delay = interval;
                }
                Err(error) => {
                    task_counters.failures.fetch_add(1, Ordering::Relaxed);
                    log::warn!("CRI reconciliation failed: {error:#}");
                    let mut stale = sender.borrow().as_ref().clone();
                    stale.stale = true;
                    sender.send_replace(Arc::new(stale));
                    delay = if delay.is_zero() {
                        Duration::from_secs(1)
                    } else {
                        (delay * 2).min(Duration::from_secs(60))
                    };
                }
            }
        }
    });
    (receiver, counters)
}

async fn reconcile(endpoint: &CriEndpoint) -> anyhow::Result<CriSnapshot> {
    let mut client = connect(&endpoint.socket).await?;
    let containers = client
        .list_containers(ListContainersRequest { filter: None })
        .await
        .context("CRI ListContainers")?
        .into_inner()
        .containers
        .into_iter()
        .map(|item| {
            let metadata = item.metadata.unwrap_or_default();
            CriContainer {
                id: item.id,
                pod_sandbox_id: item.pod_sandbox_id,
                name: metadata.name,
                attempt: metadata.attempt,
            }
        });
    let sandboxes = client
        .list_pod_sandbox(ListPodSandboxRequest { filter: None })
        .await
        .context("CRI ListPodSandbox")?
        .into_inner()
        .items
        .into_iter()
        .map(|item| {
            let metadata = item.metadata.unwrap_or_default();
            CriSandbox {
                id: item.id,
                namespace: metadata.namespace,
                pod_name: metadata.name,
                pod_uid: metadata.uid,
            }
        });
    build_snapshot(endpoint.runtime, containers, sandboxes)
}

async fn connect(socket: &Path) -> anyhow::Result<RuntimeServiceClient<tonic::transport::Channel>> {
    let socket = socket.to_path_buf();
    let channel = Endpoint::from_static("http://[::]")
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = socket.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(socket).await?)) }
        }))
        .await
        .context("connect to CRI Unix socket")?;
    Ok(RuntimeServiceClient::new(channel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_container_to_exact_pod_sandbox() {
        let snapshot = build_snapshot(
            CriRuntime::Crio,
            [CriContainer {
                id: "container-id".into(),
                pod_sandbox_id: "sandbox-id".into(),
                name: "web".into(),
                attempt: 3,
            }],
            [CriSandbox {
                id: "sandbox-id".into(),
                namespace: "shop".into(),
                pod_name: "web-0".into(),
                pod_uid: "pod-uid".into(),
            }],
        )
        .unwrap();
        let identity = &snapshot.identities["container-id"][0];
        assert_eq!(identity.runtime, CriRuntime::Crio);
        assert_eq!(identity.namespace, "shop");
        assert_eq!(identity.container_name, "web");
        assert_eq!(identity.attempt, 3);
    }

    #[test]
    fn leaves_orphaned_containers_unresolved() {
        let snapshot = build_snapshot(
            CriRuntime::Containerd,
            [CriContainer {
                id: "container-id".into(),
                pod_sandbox_id: "missing".into(),
                name: "web".into(),
                attempt: 0,
            }],
            [],
        )
        .unwrap();
        assert!(snapshot.identities.is_empty());
    }

    #[test]
    fn requires_explicit_runtime_and_absolute_socket() {
        assert!(CriEndpoint::configured("cri-o", "/run/crio/crio.sock".into()).is_ok());
        assert!(CriEndpoint::configured("mystery", "/run/mystery.sock".into()).is_err());
        assert!(CriEndpoint::configured("containerd", "relative.sock".into()).is_err());
    }
}
