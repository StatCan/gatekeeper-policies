package deny_user_pod_system_node


test_user_pod_with_system_node_toleration_is_violation {
	cluster := {
		"namespace": {
			"user-namespace": {
				"metadata": {
					"labels": {
						"namespace.statcan.gc.ca/purpose": ""
					}
				}
			}
		}
	}

	input := {"review": {"object": {
		"kind": "Pod",
		"metadata": {
			"name": "user-pod",
			"namespace": "user-namespace",
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
					"key": "data.statcan.gc.ca/classification",
					"operator": "Equal",
					"value": "sensitive",
				},
				{
					"effect": "NoSchedule",
					"key": "namespace.statcan.gc.ca/purpose",
					"operator": "Equal",
					"value": "system",
				},
				{
					"effect": "NoSchedule",
					"key": "node.statcan.gc.ca/use",
					"operator": "Equal",
					"value": "general",
				},
			],
		},
	}}}

	# Evaluate the violation with the input
	results := violation with input as input with data.inventory.cluster as cluster

	# Expect a violation
	count(results) > 0
}


test_system_pod_with_system_node_toleration_is_not_violation {
	cluster := {
		"namespace": {
			"system": {
				"metadata": {
					"labels": {
						"namespace.statcan.gc.ca/purpose": "daaas"
					}
				}
			}
		}
	}

	input := {"review": {"object": {
		"kind": "Pod",
		"metadata": {
			"name": "system-pod",
			"namespace": "system",
			"labels": {"app": "system-pod"},
		},
		"spec": {
			"containers": [{
				"name": "system-pod",
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
					"key": "data.statcan.gc.ca/classification",
					"operator": "Equal",
					"value": "sensitive",
				},
				{
					"effect": "NoSchedule",
					"key": "namespace.statcan.gc.ca/purpose",
					"operator": "Equal",
					"value": "system",
				},
				{
					"effect": "NoSchedule",
					"key": "node.statcan.gc.ca/use",
					"operator": "Equal",
					"value": "general",
				},
			],
		},
	}}}

	# Evaluate the violation with the input
	results := violation with input as input with data.inventory.cluster as cluster

	# Do not expect a violation
	count(results) == 0
}


test_daaas_pod_with_system_node_toleration_is_not_violation {
	cluster := {
		"namespace": {
			"system": {
				"metadata": {
					"labels": {
						"namespace.statcan.gc.ca/purpose": "system"
					}
				}
			}
		}
	}

	input := {"review": {"object": {
		"kind": "Pod",
		"metadata": {
			"name": "system-pod",
			"namespace": "system",
			"labels": {"app": "system-pod"},
		},
		"spec": {
			"containers": [{
				"name": "system-pod",
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
					"key": "data.statcan.gc.ca/classification",
					"operator": "Equal",
					"value": "sensitive",
				},
				{
					"effect": "NoSchedule",
					"key": "namespace.statcan.gc.ca/purpose",
					"operator": "Equal",
					"value": "system",
				},
				{
					"effect": "NoSchedule",
					"key": "node.statcan.gc.ca/use",
					"operator": "Equal",
					"value": "general",
				},
			],
		},
	}}}

	# Evaluate the violation with the input
	results := violation with input as input with data.inventory.cluster as cluster

	# Do not expect a violation
	count(results) == 0
}
