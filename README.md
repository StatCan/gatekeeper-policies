# GateKeeper Policies

Policies that are to be enforced by GateKeeper for the DAaaS Platform.

> Note: Gatekeeper is a validating / mutating webhook that enforces CRD-based policies executed by the Open Policy Agent.

## Images

A helpful command to list all of the known container images in the cluster is given below:

```sh
kubectl get pod -o json -A | jq -r '.items[].spec.containers[].image' | sed -E 's/(.*):.*/\1/g' | sort -u
```

## General

This repo contains common policies that can be used to enforce specific Kubernetes features.

| Control Aspect              | Field Names in K8S   | Gatekeeper Constraint and Constraint Template                    |
|-----------------------------|----------------------|------------------------------------------------------------------|
| Container Allowed Images    | `spec.peers`         | [container-allowed-images](general/container-allowed-images)     |
| Contaienr Limits            | `service.spec.ports` | [container-limits](general/container-limits)                     |
| Ingress Hostnames Conflict  | `spec.trafficPolicy` | [ingress-hostnames-conflict](general/ingress-hostnames-conflict) |
| Load Balancer No Public IPs | `spec.trafficPolicy` | [loadbalancer-no-public-ips](general/loadbalancer-no-public-ips) |

## Pod Security Policies

This repo contains common policies needed in Pod Security Policy but implemented as Constraints and Constraint Templates with Gatekeeper.

A [Pod Security Policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) is a cluster-level resource that controls security
sensitive aspects of the pod specification. The `PodSecurityPolicy` objects define a set of conditions that a pod must run with in order to be accepted into the system, as well as defaults for the related fields.

An administrator can control the following by setting the field in PSP or by deploying the corresponding Gatekeeper constraint and constraint templates:

| Control Aspect                                    | Field Names in PSP                                                          | Gatekeeper Constraint and Constraint Template                                |
|---------------------------------------------------|-----------------------------------------------------------------------------|------------------------------------------------------------------------------|
| Running of privileged containers                  | `privileged`                                                                | [privileged-containers](pod-security-policy/privileged-containers)           |
| Usage of host namespaces                          | `hostPID`, `hostIPC`                                                        | [host-namespaces](pod-security-policy/host-namespaces)                       |
| Usage of host networking and ports                | `hostNetwork`, `hostPorts`                                                  | [host-network-ports](pod-security-policy/host-network-ports)                 |
| Usage of volume types                             | `volumes`                                                                   | [volumes](pod-security-policy/volumes)                                       |
| Usage of the host filesystem                      | `allowedHostPaths`                                                          | [host-filesystem](pod-security-policy/host-filesystem)                       |
| White list of Flexvolume drivers                  | `allowedFlexVolumes`                                                        | [flexvolume-drivers](pod-security-policy/flexvolume-drivers)                 |
| Allocating an FSGroup that owns the pod's volumes | `fsGroup`                                                                   | [fsgroup](pod-security-policy/fsgroup)                                       |
| Requiring the use of a read only root file system | `readOnlyRootFilesystem`                                                    | [read-only-root-filesystem](pod-security-policy/read-only-root-filesystem)   |
| The user and group IDs of the container           | `runAsUser`, `runAsGroup`, `supplementalGroups`                             | [users](pod-security-policy/users)                                           |
| Restricting escalation to root privileges         | `allowPrivilegeEscalation`, `defaultAllowPrivilegeEscalation`               | [allow-privilege-escalation](pod-security-policy/allow-privilege-escalation) |
| Linux capabilities                                | `defaultAddCapabilities`, `requiredDropCapabilities`, `allowedCapabilities` | [capabilities](pod-security-policy/capabilities)                             |
| The SELinux context of the container              | `seLinux`                                                                   | [seLinux](pod-security-policy/selinux)                                       |
| The Allowed Proc Mount types for the container    | `allowedProcMountTypes`                                                     | [proc-mount](pod-security-policy/proc-mount)                                 |
| The AppArmor profile used by containers           | annotations                                                                 | [apparmor](pod-security-policy/apparmor)                                     |
| The seccomp profile used by containers            | annotations                                                                 | [seccomp](pod-security-policy/seccomp)                                       |
| The sysctl profile used by containers             | `forbiddenSysctls`,`allowedUnsafeSysctls`                                   | [forbidden-sysctls](pod-security-policy/forbidden-sysctls)                   |

## Service Mesh

This repo contains a set of common policies that can be used to enforce specific Service Mesh features.

| Control Aspect      | Field Names in Mesh  | Gatekeeper Constraint and Constraint Template           |
|---------------------|----------------------|---------------------------------------------------------|
| Peer Authentication | `spec.peers`         | [peer-authentication](service-mesh/peer-authentication) |
| Port Naming         | `service.spec.ports` | [port-naming](service-mesh/port-naming)                 |
| Traffic Policy      | `spec.trafficPolicy` | [traffic-policy](service-mesh/traffic-policy)           |

## Acknowledgements

* [Anthos](https://github.com/GoogleCloudPlatform/acm-policy-controller-library)
* [GateKeeper](https://github.com/open-policy-agent/gatekeeper/tree/master/library)
