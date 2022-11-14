# GateKeeper Policies

Policies that are to be enforced by [GateKeeper](https://github.com/open-policy-agent/gatekeeper) for the Kubernetes Platform.

> Note: Gatekeeper is a validating / mutating webhook that enforces CRD-based policies executed by the Open Policy Agent.

## Policies

### General

This repo contains general policies that can be used to enforce common Kubernetes requirements.

| Control Aspect                   | Gatekeeper Constraint Template                                               |
| -------------------------------- | ---------------------------------------------------------------------------- |
| Container Allowed Images         | [container-allowed-images](general/container-allowed-images)                 |
| Container Image Must Have Digest | [container-image-must-have-digest](general/container-image-must-have-digest) |
| Container Limits                 | [container-limits](general/container-limits)                                 |
| Deny External Users              | [deny-external-users](general/deny-external-users)                                 |
| Ingress No Hostnames             | [ingress-no-hostnames](general/ingress-no-hostnames)                         |
| Ingress Hostnames Conflict       | [ingress-hostnames-conflict](general/ingress-hostnames-conflict)             |
| Load Balancer No Public IPs      | [loadbalancer-no-public-ips](general/loadbalancer-no-public-ips)             |
| Pod Enforce Labels               | [pod-enforce-labels](general/pod-enforce-labels)                             |
| Restrict Hostnames               | [restrict-hostnames](general/restrict-hostnames/)                            |

### Pod Security Policies

This repo contains common policies replacing the deprecated `PodSecurityPolicy` into Constraint Templates using [GateKeeper](https://github.com/open-policy-agent/gatekeeper).

| Control Aspect                     | Gatekeeper Constraint Template                                                             |
| ---------------------------------- | ------------------------------------------------------------------------------------------ |
| Allowed external ips               | [allowed-external-ips](pod-security-policy/allowed-external-ips)                           |
| Allowed host paths                 | [allowed-host-paths](pod-security-policy/allowed-host-paths)                               |
| Allowed privilege escalation       | [allowed-privilege-escalation](pod-security-policy/allowed-privilege-escalation)           |
| Allowed proc mount types           | [allowed-proc-mount-types](pod-security-policy/allowed-proc-mount-types)                   |
| Allowed seccomp profiles           | [allowed-seccomp-profiles](pod-security-policy/allowed-seccomp-profiles)                   |
| Allowed users and groups           | [allowed-users-groups](pod-security-policy/allowed-users-groups)                           |
| Allowed volume types               | [allowed-volume-types](pod-security-policy/allowed-volume-types)                           |
| Block automount token              | [block-automount-token](pod-security-policy/block-automount-token)                         |
| Block default namespace            | [block-default-namespace](pod-security-policy/block-default-namespace)                     |
| Block host namespace               | [block-host-namespace](pod-security-policy/block-host-namespace)                           |
| Container capabilities             | [container-capabilities](pod-security-policy/container-capabilities)                       |
| Container no privilege escalation  | [container-no-privilege-escalation](pod-security-policy/container-no-privilege-escalation) |
| Deny Employee-Only Features        | [deny-employee-only-features](pod-security-policy/deny-employee-only-features)             |
| Deny extraction                    | [deny-extraction](pod-security-policy/deny-extraction)                                     |
| Deny pipelines                     | [deny-pipelines](pod-security-policy/deny-pipelines)                                       |
| Disk data classification           | [disk-data-classification](pod-security-policy/disk-data-classification)                   |
| Enforce apparmor profile           | [enforce-apparmor-profile](pod-security-policy/enforce-apparmor-profile)                   |
| Flexvolume drivers                 | [flexvolume-drivers](pod-security-policy/flexvolume-drivers)                               |
| Forbidden sysctls                  | [forbidden-sysctls](pod-security-policy/forbidden-sysctls-interfaces)                      |
| Host networking and ports          | [host-network-ports](pod-security-policy/host-network-ports)                               |
| Protected B Auth                   | [protectedb-auth](pod-security-policy/protectedb-auth)                                     |
| Require read only root file system | [read-only-root-filesystem](pod-security-policy/read-only-root-filesystem)                 |
| Metadata restrictions              | [metadata-restrictions](pod-security-policy/metadata-restrictions)                         |
| Namespace guardrails               | [namespace-guardrails](pod-security-policy/namespace-guardrails)                           |
| SELinux context of the container   | [seLinux](pod-security-policy/selinux)                                                     |

### Service Mesh

This repo contains a set of common policies that can be used to enforce specific Service Mesh features.

| Control Aspect      | Gatekeeper Constraint Template                          |
| ------------------- | ------------------------------------------------------- |
| Gateway             | [gateway](service-mesh/gateway)                         |
| Peer Authentication | [peer-authentication](service-mesh/peer-authentication) |
| Port Naming         | [port-naming](service-mesh/port-naming)                 |
| Traffic Policy      | [traffic-policy](service-mesh/traffic-policy)           |

## Testing

When creating a Policy, there are currently three ways of testing them:

### OPA Tests

The `opa` CLI can be used to run [tests](https://www.openpolicyagent.org/docs/latest/policy-testing) on policies.
This can be very useful since Open Policy Agent allows for easy mocking of data via the [`with` keyword](https://www.openpolicyagent.org/docs/latest/policy-testing/#data-and-function-mocking).

> These types of tests are best suited for policies which require access to data not available in the [`AdmissionReview`](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#webhook-request-and-response) API but accessed via [Gatekeeper's data replication features](https://open-policy-agent.github.io/gatekeeper/website/docs/sync).

To take advantage of automatic test running and the automatic copying of `rego` into a  `ConstraintTemplate`, the following structure needs to be followed:
- Ensure that the `ConstraintTemplate` is in a file named `template.yaml` at the root of your policy's folder
- Ensure that the `rego` files are in a folder called `rego`
  - For example: [general/restrict-hostnames/rego](./general/restrict-hostnames/rego/)
- Ensure that the `rego` that should be injected into the `ConstraintTemplate` is named `src.rego`
- Run the [`rego.sh`](./rego.sh) script to run tests and copy your source code into `template.yaml`
  - Note: requires the [`yq`](https://github.com/mikefarah/yq) utility

### Integration Tests

Integration tests are run as part of the GitHub Actions. These deploy policies to a `k3s` cluster using the [BATS](https://github.com/bats-core/bats-core) framework. It deploys the `ConstraintTemplate` for the policy, a single CustomResource of the CRD derived from the `ConstraintTemplate`, and two resources representing a passing and a failing scenario.

To take advantage of this system create the following:
- Ensure that the `ConstraintTemplate` is in a file named `template.yaml` at the root of your policy's folder
- Create a folder named `example` at the root of your policy's folder
- In the `example` folder:
  - Create a file named `constraint.yaml` with the `CustomResource` representing an implemented policy
  - Create a file named `allowed.yaml` with a resource that should pass the policy
  - Create a file named `disallowed.yaml` with a resource that should not pass the policy

### Gator

[`gator`](https://open-policy-agent.github.io/gatekeeper/website/docs/gator) is a recent addition to Gatekeeper allowing for the creation of test suites that can be run locally.

[`gator` test suites](https://open-policy-agent.github.io/gatekeeper/website/docs/gator#writing-test-suites) will be run automatically as part of the CI.

## Links

- [Rego Playground](https://play.openpolicyagent.org/)

## Acknowledgements

- [Anthos](https://github.com/GoogleCloudPlatform/acm-policy-controller-library)
- [Azure Policy](https://github.com/Azure/azure-policy/tree/master/built-in-references/Kubernetes)
- [Community Policy](https://github.com/Azure/Community-Policy)
- [Open Policy Agent](https://github.com/open-policy-agent/gatekeeper-library)
