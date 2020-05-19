# GateKeeper Policies

Policies that are to be enforced by GateKeeper for the DAaaS Platform.

> Note: Gatekeeper is a validating / mutating webhook that enforces CRD-based policies executed by the Open Policy Agent.

## Images

A helpful command to list all of the known container images in the cluster is given below:

```sh
kubectl get pod -o json -A | jq -r '.items[].spec.containers[].image' | sed -E 's/(.*):.*/\1/g' | sort -u
```
