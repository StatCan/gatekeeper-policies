package deny_user_pod_system_node

# If a user pod is submitted from a non-system namespace and contains a
# toleration allowing it to be scheduled to a system node, then the
# request should be denied.
test_user_pod_with_system_node_toleration_is_violation {
	input := {"review": {"object": {
		"kind": "Pod",
		"metadata": {
			"name": "user-pod",
			"namespace": "default",
			"labels": {"app": "user-pod"},
		},
		"spec": {
			"containers": [{
				"name": "user-pod",
				"image": "nginx:latest",
				"resources": {
					"limits": {
						"cpu": "50m",
						"memory": "50Mi",
					},
					"requests": {
						"cpu": "50m",
						"memory": "50Mi",
					},
				},
			}],
			"tolerations": [
				{
					"effect": "NoSchedule",
					"key": "classification",
					"operator": "Equal",
					"value": "sensitive",
				},
				{
					"effect": "NoSchedule",
					"key": "purpose",
					"operator": "Equal",
					"value": "system",
				},
				{
					"effect": "NoSchedule",
					"key": "use",
					"operator": "Equal",
					"value": "general",
				},
			],
		},
	}}}

	# Evaluate the violation with the input
	results := violation with input as input

	# Expect a violation
	count(results) > 0
}
