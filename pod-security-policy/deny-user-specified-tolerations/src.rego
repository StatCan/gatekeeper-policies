# @title Deny user pod from being scheduled to system nodes
#
# A number of user-specified tolerations should be rejected as these
# tolerations can be used to schedule a user pod to an inappropriate node pool.
# In particular, the following scenarios need to be checked:

# 1. If a user pod (i.e. namespace != "system") is submitted with the toleration
#    `node.statcan.gc.ca/purpose=system:NoSchedule`, then the request must be denied
#    as the user pod may be scheduled onto a system nodepool.
# 2. If an **unclassified** user pod (i.e. a pod without the label `data.statcan.gc.ca/classification: protected-b`)
#    is submitted with the toleration `data.statcan.gc.ca/classification=protected-b:NoSchedule`, then the
#    request must be denied as an unclassified pod may be scheduled onto a protected-b nodepool.
# 3. If a **protected-b** user pod (i.e. a pod with the label `data.statcan.gc.ca/classification: protected-b`)
#    is submitted with the toleration `data.statcan.gc.ca/classification=unclassified:NoSchedule`, then the
#    request must be denied as a protected-b pod may be scheduled onto an unclassified nodepool.
#
# @enforcement deny
# @kinds core/Pod
package deny_user_pod_system_node

system_namespace := "system"

violation[{"msg": msg, "details": {}}] {
	resource := input.review.object

	# Tolerate scheduling user pod to system node is forbidden
	forbidden_toleration := {
		"effect": "NoSchedule",
		"key": "node.statcan.gc.ca/purpose",
		"operator": "Equal",
		"value": "system",
	}

	# If the namespace is "system", then this policy does not apply.
	resource.metadata.namespace != system_namespace

	# If the forbidden toleration is not present, then this policy does not apply.
	tolerations := [toleration | resource.spec.tolerations[i] == forbidden_toleration; toleration := resource.spec.tolerations[i]]
	count(tolerations) > 0

	# Get pod name and namespace
	pod_name := resource.metadata.name
	namespace := resource.metadata.namespace
	msg := sprintf("Forbidden: Pod %s in namespace %s has toleration %v, which would allow it to be scheduled to a system node. Please ensure that your pod spec does not contain the specified toleration.", [pod_name, namespace, forbidden_toleration])
}


violation[{"msg": msg, "details": {}}] {
	resource := input.review.object

	# Tolerate scheduling user pod to system node is forbidden
	forbidden_toleration := {
		"effect": "NoSchedule",
		"key": "data.statcan.gc.ca/classification",
		"operator": "Equal",
		"value": "protected-b",
	}

	# If the namespace is "system", then this policy does not apply.
	resource.metadata.namespace != system_namespace

	# If the forbidden toleration is not present, then this policy does not apply.
	tolerations := [toleration | resource.spec.tolerations[i] == forbidden_toleration; toleration := resource.spec.tolerations[i]]
	count(tolerations) > 0

	# Get pod name and namespace
	pod_name := resource.metadata.name
	namespace := resource.metadata.namespace
	msg := sprintf("Forbidden: Pod %s in namespace %s has toleration %v, which would allow it to be scheduled to a system node. Please ensure that your pod spec does not contain the specified toleration.", [pod_name, namespace, forbidden_toleration])
}

violation[{"msg": msg, "details": {}}] {
	resource := input.review.object

	# Tolerate scheduling user pod to system node is forbidden
	forbidden_toleration := {
		"effect": "NoSchedule",
		"key": "node.statcan.gc.ca/purpose",
		"operator": "Equal",
		"value": "system",
	}

	# If the namespace is "system", then this policy does not apply.
	resource.metadata.namespace != system_namespace

	# If the forbidden toleration is not present, then this policy does not apply.
	tolerations := [toleration | resource.spec.tolerations[i] == forbidden_toleration; toleration := resource.spec.tolerations[i]]
	count(tolerations) > 0

	# Get pod name and namespace
	pod_name := resource.metadata.name
	namespace := resource.metadata.namespace
	msg := sprintf("Forbidden: Pod %s in namespace %s has toleration %v, which would allow it to be scheduled to a system node. Please ensure that your pod spec does not contain the specified toleration.", [pod_name, namespace, forbidden_toleration])
}