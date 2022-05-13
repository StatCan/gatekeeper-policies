# GateKeeper Policies

![Kubernetes Admission Controllers Diagram](https://d33wubrfki0l68.cloudfront.net/af21ecd38ec67b3d81c1b762221b4ac777fcf02d/7c60e/images/blog/2019-03-21-a-guide-to-kubernetes-admission-controllers/admission-controller-phases.png)

Recall that there are two kinds of admission control webhooks in Kubernetes: (1) mutating admission webhooks, and (2) validating admission webhooks.[^1] [Gatekeeper](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/) is a **validating admission webhook** that enforces policies executed by [Open Policy Agent (OPA)](https://www.openpolicyagent.org).

[^1] Diagram borrowed from [Kubernetes Admission Controllers Documentation](https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/)

This repository contains policies that are enforced by [GateKeeper](https://github.com/open-policy-agent/gatekeeper) for the Kubernetes Platform.

## Prerequisites

We recommend installing the following software locally to test your rego policies.

- [Open Policy Agent](https://www.openpolicyagent.org/docs/v0.11.0/get-started/)
- [Konstraint](https://github.com/plexsystems/konstraint)

## How to Contribute

> TODO: update with Taskfile commands once it is set up

1. Create a folder in this repository with a semantically meaningful name (i.e. it should be clear from the name what the policy relates to). Additionally, you should place your policy under the broader category that it relates to (e.g. `pod-security-policy`).
2. In your folder, create a file called `src.rego`. Structure your `src.rego` file in the way shown below; this allows `ConstraintTemplates` and `Constraints` to be automatically generated from your rego policy.

```rego
# @title <title of your policy>
#
# Written description of your policy
#
# @enforcement deny # Can be either "deny" or "dryrun"
# @kinds <group/resource type that the constraint applies to>
package <name of rego policy>


violation[{"msg": msg, "details": {}}] {
    # Business logic of rego policy goes here
}
```

3. Create a file called `src_test.rego` that contains one or more unit tests written against the policy defined in `src.rego`. The test code should be structured as follows (roughly). Note that you would either indicate `count(results) > 0` if you *expect* a violation **or** `count(results) == 0` if you *do not expect* a violation.

```rego
package deny_user_pod_system_node

# Include a short description of what this test case is verifying.
test_short_description_of_what_this_is_testing {
	input := {
        # Your input spec goes here
    }

	# Evaluate the violation with the input
	results := violation with input as input

	# Expect a violation
	count(results) > 0

    # Do not expect a violation
    count(results) == 0
}
```

4. Run `opa test -v .` to test (in verbose mode) the rego policy in the current directory. The output will indicate whether all of the opa unit tests are passing.
5. Run `konstraint create src.rego --skip-constraints` to auto-generate the `template.yaml` file containing the `ConstraintTemplate` for the current Gatekeeper policy.
6. Run `konstraint doc src.rego --output README.md` to auto-generate documentation for the current Gatekeeper policy.

## General

This repo contains general policies that can be used to enforce common Kubernetes requirements.

| Control Aspect                   | Gatekeeper Constraint Template                                               |
| -------------------------------- | ---------------------------------------------------------------------------- |
| Container Allowed Images         | [container-allowed-images](general/container-allowed-images)                 |
| Container Image Must Have Digest | [container-image-must-have-digest](general/container-image-must-have-digest) |
| Container Limits                 | [container-limits](general/container-limits)                                 |
| Deny External Users              | [deny-external-users](general/deny-external-users)                           |
| Ingress No Hostnames             | [ingress-no-hostnames](general/ingress-no-hostnames)                         |
| Ingress Hostnames Conflict       | [ingress-hostnames-conflict](general/ingress-hostnames-conflict)             |
| Load Balancer No Public IPs      | [loadbalancer-no-public-ips](general/loadbalancer-no-public-ips)             |
| Pod Enforce Labels               | [pod-enforce-labels](general/pod-enforce-labels)                             |

## Pod Security Policies

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

## Service Mesh

This repo contains a set of common policies that can be used to enforce specific Service Mesh features.

| Control Aspect      | Gatekeeper Constraint Template                          |
| ------------------- | ------------------------------------------------------- |
| Gateway             | [gateway](service-mesh/gateway)                         |
| Peer Authentication | [peer-authentication](service-mesh/peer-authentication) |
| Port Naming         | [port-naming](service-mesh/port-naming)                 |
| Traffic Policy      | [traffic-policy](service-mesh/traffic-policy)           |


## Links

- [Rego Playground](https://play.openpolicyagent.org/)

## Acknowledgements

- [Anthos](https://github.com/GoogleCloudPlatform/acm-policy-controller-library)
- [Azure Policy](https://github.com/Azure/azure-policy/tree/master/built-in-references/Kubernetes)
- [Community Policy](https://github.com/Azure/Community-Policy)
- [Open Policy Agent](https://github.com/open-policy-agent/gatekeeper-library)

