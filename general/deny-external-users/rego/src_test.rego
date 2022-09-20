package denyexternalusers

test_rolebinding_employee_allowed_sas_feature {
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
				"name": "alice.smith@statcan.gc.ca",
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

	# Do not expect a violation
	count(results) == 0
}


test_rolebinding_employee_allowed_non_sas_feature {
    cluster := {
            "kubeflow.org/v1": {
                "Profile": {
                    "blair-drummond": {
                        "metadata": {
                            "labels": {
                                "state.aaw.statcan.gc.ca/exists-non-cloud-main-user": "false",
                                "state.aaw.statcan.gc.ca/exists-non-sas-notebook-user": "false",
                                "state.aaw.statcan.gc.ca/has-sas-notebook-feature": "false"
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
				"name": "alice.smith@cloud.statcan.ca",
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

	# Do not expect a violation
	count(results) == 0
}

test_rolebinding_non_employee_exception_allowed_sas_feature {
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
				"name": "jane.doe@notanemployee.ca",
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

	# Do not expect a violation
	count(results) == 0
}

test_rolebinding_non_employee_exception_allowed_non_sas_feature {
    cluster := {
            "kubeflow.org/v1": {
                "Profile": {
                    "blair-drummond": {
                        "metadata": {
                            "labels": {
                                "state.aaw.statcan.gc.ca/exists-non-cloud-main-user": "false",
                                "state.aaw.statcan.gc.ca/exists-non-sas-notebook-user": "false",
                                "state.aaw.statcan.gc.ca/has-sas-notebook-feature": "false"
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

	# Do not expect a violation
	count(results) == 0
}

test_rolebinding_non_employee_non_exception_denied_sas_feature {
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
				"name": "john.doe@external.ca",
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

	# Expect a violation
	count(results) > 0
}

test_rolebinding_non_employee_non_exception_allowed_non_sas_feature {
    cluster := {
            "kubeflow.org/v1": {
                "Profile": {
                    "blair-drummond": {
                        "metadata": {
                            "labels": {
                                "state.aaw.statcan.gc.ca/exists-non-cloud-main-user": "false",
                                "state.aaw.statcan.gc.ca/exists-non-sas-notebook-user": "false",
                                "state.aaw.statcan.gc.ca/has-sas-notebook-feature": "false"
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
				"name": "john.doe@external.ca",
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

	# Expect a violation
	count(results) == 0
}
