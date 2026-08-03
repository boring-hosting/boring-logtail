// SPDX-License-Identifier: GPL-3.0-or-later

//! Parses kubelet's node-local CRI log topology without reading log payloads.

use anyhow::{Context as _, bail};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CriLogIdentity {
    pub node: String,
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub container_name: String,
    pub opaque_container_id: String,
    pub attempt: u32,
    pub log_path: PathBuf,
}

pub fn identity_from_link(
    link: &Path,
    target: &Path,
    resolved_log_path: PathBuf,
    node: &str,
) -> anyhow::Result<CriLogIdentity> {
    let filename = link
        .file_name()
        .and_then(|name| name.to_str())
        .context("container log filename is not UTF-8")?;
    let filename = filename
        .strip_suffix(".log")
        .context("container log filename does not end in .log")?;
    let mut fields = filename.splitn(3, '_');
    let pod_name = nonempty(fields.next()).context("missing Pod name")?;
    let namespace = nonempty(fields.next()).context("missing namespace")?;
    let container_and_id = fields.next().context("missing container name and ID")?;
    let (container_name, opaque_container_id) = container_and_id
        .rsplit_once('-')
        .context("missing container ID suffix")?;
    if container_name.is_empty()
        || opaque_container_id.len() != 64
        || !opaque_container_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("container name or opaque ID is malformed");
    }

    let attempt = target
        .file_stem()
        .and_then(|value| value.to_str())
        .context("log target attempt is not UTF-8")?
        .parse::<u32>()
        .context("log target attempt is not an integer")?;
    let target_container = target
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .context("log target has no container directory")?;
    let pod_directory = target
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .context("log target has no Pod directory")?;
    let mut pod_fields = pod_directory.splitn(3, '_');
    let target_namespace = pod_fields.next().context("target missing namespace")?;
    let target_pod = pod_fields.next().context("target missing Pod name")?;
    let pod_uid = nonempty(pod_fields.next()).context("target missing Pod UID")?;

    if namespace != target_namespace || pod_name != target_pod || container_name != target_container
    {
        bail!("container log link and target identity disagree");
    }

    Ok(CriLogIdentity {
        node: node.to_owned(),
        namespace: namespace.to_owned(),
        pod_name: pod_name.to_owned(),
        pod_uid: pod_uid.to_owned(),
        container_name: container_name.to_owned(),
        opaque_container_id: opaque_container_id.to_owned(),
        attempt,
        log_path: resolved_log_path,
    })
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn parses_identity_without_guessing_the_runtime() {
        let link = PathBuf::from(format!(
            "/var/log/containers/checkout-abc_payments_checkout-{ID}.log"
        ));
        let target = Path::new("/var/log/pods/payments_checkout-abc_pod-uid/checkout/2.log");
        let identity = identity_from_link(&link, target, target.into(), "worker-1").unwrap();

        assert_eq!(identity.namespace, "payments");
        assert_eq!(identity.pod_name, "checkout-abc");
        assert_eq!(identity.pod_uid, "pod-uid");
        assert_eq!(identity.container_name, "checkout");
        assert_eq!(identity.opaque_container_id, ID);
        assert_eq!(identity.attempt, 2);
        assert_eq!(identity.node, "worker-1");
    }

    #[test]
    fn rejects_disagreement_and_partial_ids() {
        let link = PathBuf::from(format!(
            "/var/log/containers/checkout-abc_payments_checkout-{ID}.log"
        ));
        let wrong = Path::new("/var/log/pods/other_checkout-abc_pod-uid/checkout/0.log");
        assert!(identity_from_link(&link, wrong, wrong.into(), "worker-1").is_err());

        let short = Path::new("/var/log/containers/pod_ns_container-abc.log");
        let target = Path::new("/var/log/pods/ns_pod_uid/container/0.log");
        assert!(identity_from_link(short, target, target.into(), "worker-1").is_err());
    }
}
