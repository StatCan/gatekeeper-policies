package denyemployeeonlyfeatures

test_create_sas_pod_in_ns_with_non_sas_user {
    cluster := {
            "kubeflow.org/v1": {
                "Profile": {
                    "blair-drummond": {
                        "metadata": {
                            "labels": {
                                "state.aaw.statcan.gc.ca/exists-non-sas-notebook-user": "true"
                            }
                        }
                    }
                }
            }
        }
	input := {
		"review": {"object": {
		"kind": "Pod",
		"metadata": {
			"namespace": "blair-drummond"
		},
		"spec": {
			"containers": [{
				"name": "user-pod",
				"image": "k8scc01covidacr.azurecr.io/sas:latest",
			}]
		},
	}}}

	# Evaluate the violation with the input
	results := violation with input as input with data.inventory.cluster as cluster

	# Expect a violation
	count(results) > 0
}

test_create_non_sas_pod_in_ns_with_non_sas_user {
    cluster := {
            "kubeflow.org/v1": {
                "Profile": {
                    "blair-drummond": {
                        "metadata": {
                            "labels": {
                                "state.aaw.statcan.gc.ca/exists-non-sas-notebook-user": "true"
                            }
                        }
                    }
                }
            }
        }
	input := {
		"review": {"object": {
		"kind": "Pod",
		"metadata": {
			"namespace": "blair-drummond"
		},
		"spec": {
			"containers": [{
				"name": "user-pod",
				"image": "nginx:latest",
			}]
		},
	}}}

	# Evaluate the violation with the input
	results := violation with input as input with data.inventory.cluster as cluster

	# Do not expect a violation
	count(results) == 0
}

test_create_sas_pod_in_ns_with_sas_users {
    cluster := {
            "kubeflow.org/v1": {
                "Profile": {
                    "blair-drummond": {
                        "metadata": {
                            "labels": {
                                "state.aaw.statcan.gc.ca/exists-non-sas-notebook-user": "false"
                            }
                        }
                    }
                }
            }
        }
	input := {
		"review": {"object": {
		"kind": "Pod",
		"metadata": {
			"namespace": "blair-drummond"
		},
		"spec": {
			"containers": [{
				"name": "user-pod",
				"image": "k8scc01covidacr.azurecr.io/sas:latest",
			}]
		},
	}}}

	# Evaluate the violation with the input
	results := violation with input as input with data.inventory.cluster as cluster

	# Do not expect a violation
	count(results) == 0
}

test_create_non_sas_pod_in_ns_with_sas_users {
    cluster := {
            "kubeflow.org/v1": {
                "Profile": {
                    "blair-drummond": {
                        "metadata": {
                            "labels": {
                                "state.aaw.statcan.gc.ca/exists-non-sas-notebook-user": "false"
                            }
                        }
                    }
                }
            }
        }
	input := {
		"review": {"object": {
		"kind": "Pod",
		"metadata": {
			"namespace": "blair-drummond"
		},
		"spec": {
			"containers": [{
				"name": "user-pod",
				"image": "nginx:latest",
			}]
		},
	}}}

	# Evaluate the violation with the input
	results := violation with input as input with data.inventory.cluster as cluster

	# Do not expect a violation
	count(results) == 0
}