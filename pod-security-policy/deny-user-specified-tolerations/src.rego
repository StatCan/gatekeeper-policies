# @title Deny pods from being scheduled to inappropriate nodes
#
# A number of user-specified tolerations should be rejected as these
# tolerations can be used to schedule a user pod to an inappropriate node pool.
# In particular, the following scenarios need to be checked:
#
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
# ## Test Cases
# 1. If a pod is submitted from a **non-system namespace** and contains a toleration
#    allowing it to be scheduled to a **system node**, then the request should be **denied**.
# 2. If a pod is submitted from a **system namespace** and it contains a toleration
#    allowing it to be scheduled to a **system node**, then the request should be **allowed**.
# 3. If a pod is submitted from a **daaas namespace** and it contains a toleration
#    allowing it to be scheduled to a **system node**, then the request should be **allowed**.
# 4. If an **unclassified pod** is submitted from a **user namespace** and it contains a toleration
#    allowing it to be scheduled to a **protected-b node**, then the request should be **denied**.
# 5. If a **protected-b pod** is submitted from a **user namespace**, and it contains a toleration
#    allowing it to be scheduled to a **protected-b node**, then the request should be **allowed**.
# 6. If a **protected-b pod** is submitted from a **user namespace** and it contains a toleration
#    allowing it to be scheduled to an **unclassified node**, then the request should be **denied**.
# 7. If an **unclassified pod** is submitted from a **user namespace**, and it contains a toleration
#    allowing it to be scheduled to an **unclassified node**, then the request should be **allowed**.
#
# @enforcement deny
# @kinds core/Pod
package deny_user_pod_system_node

system_namespace_label = "namespace.statcan.gc.ca/purpose"
system_namespace = ["system", "daaas"]

classification_label = "data.statcan.gc.ca/classification"

is_system_namespace(pod) {
	# Get the namespace object that the pod belongs to
	namespace := data.inventory.cluster["namespace"][pod.metadata.namespace]
	# Note: can also access namespaced resources this way, e.g.
	# data.inventory.namespace["your namespace"].rolebindings["myrolebinding"]...

	# If the namespace has purpose "system", then this policy does not apply.
	ns := namespace.metadata.labels[system_namespace_label]
	count([system | system := system_namespace[_]; system == ns]) > 0
}


violation[{"msg": msg, "details": {}}] {
	resource := input.review.object

	# Check if any toleration has the purpose key - if this key doesn't exist, the user doesn't have this toleration.
	purpose_toleration := resource.spec.tolerations[_]
	purpose_toleration["key"] == system_namespace_label
	purpose_toleration["value"] == "system"

	not is_system_namespace(resource)

	# Get pod name and namespace
	pod_name := resource.metadata.name
	namespace := resource.metadata.namespace
	msg := sprintf("Forbidden: Pod %s in namespace %s has toleration %s:%s, which would allow it to be scheduled to a system node. Please ensure that your pod spec does not contain the specified toleration.", [pod_name, namespace, purpose_toleration["key"], purpose_toleration["value"]])
}

violation[{"msg": msg, "details": {}}] {
	resource := input.review.object

	# Check if any toleration has the purpose key - if this key doesn't exist, the user doesn't have this toleration.
	purpose_toleration := resource.spec.tolerations[_]
	purpose_toleration["key"] == classification_label
	purpose_toleration["value"] == "protected-b"

	# Check if classification label is absent or unclassified, this pod must not go to a protected-b node pool
	not resource.metadata.labels[classification_label] == "protected-b"

	not is_system_namespace(resource)


	# Get pod name and namespace
	pod_name := resource.metadata.name
	namespace := resource.metadata.namespace
	msg := sprintf("Forbidden: Pod %s in namespace %s has toleration %s:%s, which would allow it to be scheduled to a protected-b node. Please ensure that your pod spec does not contain the specified toleration.", [pod_name, namespace, purpose_toleration["key"], purpose_toleration["value"]])
}

violation[{"msg": msg, "details": {}}] {
	resource := input.review.object

	# Check if any toleration has the purpose key - if this key doesn't exist, the user doesn't have this toleration.
	purpose_toleration := resource.spec.tolerations[_]
	purpose_toleration["key"] == classification_label
	purpose_toleration["value"] == "unclassified"

	# Check if classification label is absent or unclassified, this pod must not go to a protected-b node pool
	resource.metadata.labels[classification_label] == "protected-b"

	not is_system_namespace(resource)


	# Get pod name and namespace
	pod_name := resource.metadata.name
	namespace := resource.metadata.namespace
	msg := sprintf("Forbidden: Pod %s in namespace %s has toleration %s:%s, which would allow it to be scheduled to an unclassified node. Please ensure that your pod spec does not contain the specified toleration.", [pod_name, namespace, purpose_toleration["key"], purpose_toleration["value"]])
}
