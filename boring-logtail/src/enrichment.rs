// SPDX-License-Identifier: GPL-3.0-or-later

//! Node-local Kubernetes identity snapshot used by CRI-file capture.

use std::collections::HashMap;

use blt_model::{ContainerId, KubernetesIdentity};

#[derive(Clone, Debug, Default)]
pub struct PodSnapshot {
    pub identities: HashMap<ContainerId, Vec<KubernetesIdentity>>,
    pub ready: bool,
    pub stale: bool,
    pub over_capacity: bool,
}
