package denyexternalusers

test_rolebinding_add_non_employee_to_ns_with_sas_feature_present {
    cluster := {
            "kubeflow.org/v1": {
                "Profile": {
                    "blair-drummond": {
                        "metadata": {
                            "labels": {
                                "state.aaw.statcan.gc.ca/exists-non-cloud-main-user": "false",
                                "state.aaw.statcan.gc.ca/exists-non-sas-notebook-user": "false",
                                "state.aaw.statcan.gc.ca/has-sas-notebook-feature": "true"
                            }
                        }
                    }
                }
            }
        }
	input := {
		"review": {"object": {
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind": "RoleBinding",
			"metadata": {
				"annotations": {
					"role": "edit",
					"user": "collin.brown@external.ca",
				},
				"name": "user-collin-brown-cloud-statcan-ca-clusterrole-edit",
				"namespace": "blair-drummond",
			},
			"roleRef": {
				"apiGroup": "rbac.authorization.k8s.io",
				"kind": "ClusterRole",
				"name": "kubeflow-edit",
			},
			"subjects": [{
				"apiGroup": "rbac.authorization.k8s.io",
				"kind": "User",
				"name": "alice.smith@external.ca",
			}],
		}},
		"parameters": {
			"labels": ["state.aaw.statcan.gc.ca/has-sas-notebook-feature"],
			"employeeDomains": [
				"cloud.statcan.ca",
				"statcan.gc.ca",
			],
            "sasNotebookExceptions": [
                "alice.smith@external.ca",
                "jane.doe@notanemployee.ca"
            ]
		},
	}

	# Evaluate the violation with the input
	results := violation with input as input with data.inventory.cluster as cluster

	# Expect a violation because namespace has sas feature and we are adding non employee user with no exception
	count(results) > 0
}
