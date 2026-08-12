// SPDX-License-Identifier: GPL-3.0-or-later

//! Small immutable projections of the configured capture policy.

use crate::{config::Config, enrichment::Enrichment};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PodWatchPlan {
    AllNamespaces,
    Namespaces(Vec<String>),
}

#[derive(Clone, Debug)]
pub struct WriteFilterPlan {
    namespaces: Option<BTreeSet<String>>,
}

#[derive(Clone, Debug)]
pub struct FilterPlan {
    pub pod_watch: PodWatchPlan,
    pub writes: WriteFilterPlan,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DropReason {
    Namespace,
    UnresolvedIdentity,
    AmbiguousIdentity,
    Sampled,
}

impl FilterPlan {
    pub fn compile(config: &Config) -> Self {
        let namespaces = config
            .filters
            .namespaces
            .as_ref()
            .map(|filter| filter.include.iter().cloned().collect::<BTreeSet<_>>());
        let pod_watch = namespaces
            .as_ref()
            .map_or(PodWatchPlan::AllNamespaces, |set| {
                PodWatchPlan::Namespaces(set.iter().cloned().collect())
            });
        Self {
            writes: WriteFilterPlan { namespaces },
            pod_watch,
        }
    }
}

impl WriteFilterPlan {
    pub fn evaluate(&self, enrichment: &Enrichment) -> Result<(), DropReason> {
        let Some(namespaces) = &self.namespaces else {
            return Ok(());
        };
        match enrichment {
            Enrichment::Enriched(identity) | Enrichment::Stale(identity) => {
                if namespaces.contains(&identity.namespace) {
                    Ok(())
                } else {
                    Err(DropReason::Namespace)
                }
            }
            Enrichment::UnresolvedCgroup | Enrichment::UnresolvedContainer(_) => {
                Err(DropReason::UnresolvedIdentity)
            }
            Enrichment::AmbiguousCgroup | Enrichment::AmbiguousContainer(_) => {
                Err(DropReason::AmbiguousIdentity)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrichment::{ContainerId, KubernetesIdentity};

    #[test]
    fn planning_preserves_all_namespaces_or_scopes_exactly() {
        let all = FilterPlan::compile(&Config::default());
        assert_eq!(all.pod_watch, PodWatchPlan::AllNamespaces);

        let mut config: Config =
            serde_yaml::from_str("filters:\n  namespaces:\n    include: [zebra, alpha]\n").unwrap();
        config.validate().unwrap();
        let scoped = FilterPlan::compile(&config);
        assert_eq!(
            scoped.pod_watch,
            PodWatchPlan::Namespaces(vec!["alpha".into(), "zebra".into()])
        );
    }

    #[test]
    fn namespace_filter_distinguishes_identity_outcomes() {
        let mut config: Config =
            serde_yaml::from_str("filters: {namespaces: {include: [yes]}}\n").unwrap();
        config.validate().unwrap();
        let plan = FilterPlan::compile(&config);
        assert_eq!(plan.pod_watch, PodWatchPlan::Namespaces(vec!["yes".into()]));
        let id: ContainerId = format!("containerd://{}", "a".repeat(64)).parse().unwrap();
        let identity = KubernetesIdentity {
            node: "n".into(),
            namespace: "yes".into(),
            pod_name: "p".into(),
            pod_uid: "u".into(),
            container_name: "c".into(),
            container_id: id.clone(),
            workload: crate::enrichment::WorkloadResolution::NoController,
        };
        assert_eq!(
            plan.writes
                .evaluate(&Enrichment::Enriched(identity.clone())),
            Ok(())
        );
        assert_eq!(plan.writes.evaluate(&Enrichment::Stale(identity)), Ok(()));
        let excluded = KubernetesIdentity {
            node: "n".into(),
            namespace: "no".into(),
            pod_name: "p".into(),
            pod_uid: "u".into(),
            container_name: "c".into(),
            container_id: id.clone(),
            workload: crate::enrichment::WorkloadResolution::NoController,
        };
        assert_eq!(
            plan.writes.evaluate(&Enrichment::Enriched(excluded)),
            Err(DropReason::Namespace)
        );
        assert_eq!(
            plan.writes
                .evaluate(&Enrichment::UnresolvedContainer(id.clone())),
            Err(DropReason::UnresolvedIdentity)
        );
        assert_eq!(
            plan.writes.evaluate(&Enrichment::AmbiguousContainer(id)),
            Err(DropReason::AmbiguousIdentity)
        );
    }
}
