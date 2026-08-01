// SPDX-License-Identifier: GPL-3.0-or-later

// HashMap<CgroupId, ContainerMetadata>
// HashMap<ContainerId, ContainerMetadata>

// {
//   "timestamp": "...",
//   "stream": "stdout",
//   "message": "application bytes after framing",
//   "kubernetes": {
//     "node": "worker-1",
//     "namespace": "payments",
//     "pod": "checkout-7f86d...",
//     "pod_uid": "...",
//     "container": "checkout",
//     "container_id": "containerd://...",
//     "restart_attempt": 2,
//     "workload": {
//       "kind": "Deployment",
//       "name": "checkout"
//     },
//     "application": "checkout"
//   },
//   "process": {
//     "pid": 123,
//     "tid": 124
//   },
//   "capture": {
//     "cgroup_id": 456,
//     "integrity": "complete"
//   }
// }

// This is the reconstruction Metadata
struct ContainerMetadata {
    node: String,
    namespace: String,
    pod_name: String,
    pod_uid: String,
    container_name: String,
    container_id: String,
    restart_attempt: u32,
    workload_kind: Option<String>,
    workload_name: Option<String>,
    application: Option<String>,
    labels: HashMap<String, String>,
}
