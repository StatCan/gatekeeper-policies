package restricthostnames

# Ensure that the normalization function correctly normalizes without the loss of data.
test_normalize_hosts {
	hosts := json.unmarshal(`[{"host": "www.statcan.gc.ca","path": "/"}, {"host": "example.acme.com","path":"/acme/example"}, {"host": "example.acme.com","path":"/acme/OTHER"}, {"host": "test.com","path":""}]`)

	expected_hosts := [{"host": "www.statcan.gc.ca", "path": "/"}, {"host": "example.acme.com", "path": "/acme/example"}, {"host": "example.acme.com", "path": "/acme/other"}, {"host": "test.com", "path": ""}]

	expected_hosts == normalize_hosts(hosts)
}

# Ensures that prefix allowance works correctly.
test_prefix_pass {
	namespaces := {"test-prefix-pass": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/"}]`},
			"name": "test-prefix-pass",
		},
	}}

	host := "test.com"
	path := "/pass"

	is_allowed(host, path) with input.review.object.metadata.namespace as "test-prefix-pass" with data.inventory.cluster.v1.Namespace as namespaces
}

# Test for any path under a host
test_ingress_allow_all {
	ingress := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.k8s.io",
				"kind": "Ingress",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "prod",
					"namespace": "test",
				},
				"spec": {"rules": [{
					"host": "test.com",
					"http": {"paths": [
						{
							"path": "/finance",
							"backend": {
								"serviceName": "banking",
								"servicePort": 443,
							},
						},
						{
							"path": "/other",
							"backend": {
								"serviceName": "banking",
								"servicePort": 443,
							},
						},
					]},
				}]},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/"}]`},
			"name": "test",
		},
	}}

	result := violation with input as ingress with data.inventory.cluster.v1.Namespace as namespaces

	# If result set is empty, no violations
	result == set()
}

# Test case mismatch in a path
test_ingress_case_mismatch {
	ingress := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.k8s.io",
				"kind": "Ingress",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "prod",
					"namespace": "test",
				},
				"spec": {"rules": [{
					"host": "test.com",
					"http": {"paths": [
						{
							"path": "/FINANCE",
							"backend": {
								"serviceName": "banking",
								"servicePort": 443,
							},
						},
						{
							"path": "/finANCE/billing",
							"backend": {
								"serviceName": "billing",
								"servicePort": 443,
							},
						},
					]},
				}]},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/FINance"}]`},
			"name": "test",
		},
	}}

	result := violation with input as ingress with data.inventory.cluster.v1.Namespace as namespaces

	# If result set is empty, no violations
	result == set()
}

# Test for an empty path
test_ingress_empty_path {
	ingress := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.k8s.io",
				"kind": "Ingress",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "prod",
					"namespace": "test",
				},
				"spec": {"rules": [{
					"host": "test.com",
					"http": {"paths": [
						{
							"path": "/finance",
							"backend": {
								"serviceName": "banking",
								"servicePort": 443,
							},
						},
						{
							"path": "/other",
							"backend": {
								"serviceName": "banking",
								"servicePort": 443,
							},
						},
					]},
				}]},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":""}]`},
			"name": "test",
		},
	}}

	result := violation with input as ingress with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# If result set is empty, no violations
	result == set()
}

# Test for ingress with allowed path.
test_ingress_allowed_path {
	ingress := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.k8s.io",
				"kind": "Ingress",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "prod",
					"namespace": "test",
				},
				"spec": {"rules": [{
					"host": "test.com",
					"http": {"paths": [{
						"path": "/finance",
						"backend": {
							"serviceName": "banking",
							"servicePort": 443,
						},
					}]},
				}]},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/finance"}]`},
			"name": "test",
		},
	}}

	result := violation with input as ingress with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Empty set means no violations
	result == set()
}

# Test for ingress with 2 paths, one of which is not allowed.
test_ingress_unallowed_path {
	ingress := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.k8s.io",
				"kind": "Ingress",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "prod",
					"namespace": "test",
				},
				"spec": {"rules": [{
					"host": "test.com",
					"http": {"paths": [
						{
							"path": "/finance",
							"backend": {
								"serviceName": "banking",
								"servicePort": 443,
							},
						},
						{
							"path": "/other",
							"backend": {
								"serviceName": "banking",
								"servicePort": 443,
							},
						},
					]},
				}]},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/finance"}]`},
			"name": "test",
		},
	}}

	result := violation with input as ingress with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# 1 message for /other which is not allowed.
	print(result)
	count(result) > 0
}

# Test for Ingress and Namespace without annotation.
test_ingress_no_annotation {
	ingress := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.k8s.io",
				"kind": "Ingress",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "prod",
					"namespace": "test",
				},
				"spec": {"rules": [{
					"host": "test.com",
					"http": {"paths": [
						{
							"path": "/finance",
							"backend": {
								"serviceName": "banking",
								"servicePort": 443,
							},
						},
						{
							"path": "/other",
							"backend": {
								"serviceName": "banking",
								"servicePort": 443,
							},
						},
					]},
				}]},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {},
			"name": "test",
		},
	}}

	result := violation with input as ingress with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# result with entry means there was a violation
	print(result)
	count(result) > 0
}

# Test for Ingress with an exempt host.
test_ingress_exempt {
	ingress := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.k8s.io",
				"kind": "Ingress",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "prod",
					"namespace": "test",
				},
				"spec": {"rules": [{
					"host": "testing.test.com",
					"http": {"paths": [
						{
							"path": "/finance",
							"backend": {
								"serviceName": "banking",
								"servicePort": 443,
							},
						},
						{
							"path": "/other",
							"backend": {
								"serviceName": "banking",
								"servicePort": 443,
							},
						},
					]},
				}]},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {},
			"name": "test",
		},
	}}

	exemptions := ["*.test.com"]

	result := violation with input as ingress with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Empty set means no violations
	result == set()
}

# Test for an allowed VS.
test_vs_allowed {
	vs_review := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.istio.io",
				"kind": "VirtualService",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "test",
					"namespace": "test",
				},
				"spec": {
					"hosts": ["test.com"],
					"http": [{"match": [{"uri": {"prefix": "/finance"}}, {"uri": {"exact": "/finance"}}, {"uri": {"regex": "^/finance"}}]}],
					"tcp": [{"route": [{"destination": {"host": "finance.test.scv.cluster.local"}}]}],
					"tls": [{"match": [{"sniHosts": ["finance.test.scv.cluster.local"]}]}],
				},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/finance"},{"host": "testing.com","path":"/finance"}]`},
			"name": "test",
		},
	}}

	exemptions := [""]

	result := violation with input as vs_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Empty set means no violations
	result == set()
}

# Test for a VS with a wrong host.
test_vs_wrong_host {
	vs_review := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.istio.io",
				"kind": "VirtualService",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "test",
					"namespace": "test",
				},
				"spec": {
					"hosts": ["testing.com"],
					"http": [{"match": [{"uri": {"prefix": "/finance"}}, {"uri": {"prefix": "/other"}}]}],
					"tcp": [{"route": [{"destination": {"host": "finance.test.scv.cluster.local"}}]}],
					"tls": [{"match": [{"sniHosts": ["finance.test.scv.cluster.local"]}]}],
				},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/finance"}]`},
			"name": "test",
		},
	}}

	exemptions := [""]

	result := violation with input as vs_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	count(result) > 0
	print(result)
}

# Test for VirtualService with multiple hosts, though only 1 is allowed.
test_vs_multi_host_fail {
	vs_review := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.istio.io",
				"kind": "VirtualService",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "test",
					"namespace": "test",
				},
				"spec": {
					"hosts": ["testing.com", "test.com"],
					"http": [{"match": [{"uri": {"prefix": "/finance"}}]}],
					"tcp": [{"route": [{"destination": {"host": "finance.test.scv.cluster.local"}}]}],
					"tls": [{"match": [{"sniHosts": ["finance.test.scv.cluster.local"]}]}],
				},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/finance"}]`},
			"name": "test",
		},
	}}

	exemptions := [""]

	result := violation with input as vs_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Empty set means no violations
	print(result)
	count(result) > 0
}

# Test for VirtualService with multiple allowed hosts.
test_vs_multi_host {
	vs_review := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.istio.io",
				"kind": "VirtualService",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "test",
					"namespace": "test",
				},
				"spec": {
					"hosts": ["testing.com", "test.com"],
					"http": [{"match": [{"uri": {"prefix": "/finance"}}]}],
					"tcp": [{"route": [{"destination": {"host": "finance.test.scv.cluster.local"}}]}],
					"tls": [{"match": [{"sniHosts": ["finance.test.scv.cluster.local"]}]}],
				},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/finance"},{"host": "testing.com","path":"/finance"}]`},
			"name": "test",
		},
	}}

	exemptions := [""]

	result := violation with input as vs_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Empty set means no violations
	result == set()
}

# Test for VirtualService and Namespace without annotation.
test_vs_no_annotation {
	vs_review := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.istio.io",
				"kind": "VirtualService",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "test",
					"namespace": "test",
				},
				"spec": {
					"hosts": ["testing.com", "test.com"],
					"http": [{"match": [{"uri": {"prefix": "/finance"}}]}],
					"tcp": [{"route": [{"destination": {"host": "finance.test.scv.cluster.local"}}]}],
					"tls": [{"match": [{"sniHosts": ["finance.test.scv.cluster.local"]}]}],
				},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {},
			"name": "test",
		},
	}}

	exemptions := [""]

	result := violation with input as vs_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	count(result) > 0
	print(result)
}

# Test to exempt hostnames from within the namespace.
test_vs_exempt_namespace_hosts {
	vs_review := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.istio.io",
				"kind": "VirtualService",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "test",
					"namespace": "billing",
				},
				"spec": {
					"hosts": ["finance.billing.svc", "finance.billing.svc.cluster.local"],
					"http": [{"match": [{"uri": {"prefix": "/finance"}}]}],
					"tcp": [{"route": [{"destination": {"host": "finance.test.scv.cluster.local"}}]}],
					"tls": [{"match": [{"sniHosts": ["finance.test.scv.cluster.local"]}]}],
				},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {},
			"name": "test",
		},
	}}

	exemptions := [""]

	result := violation with input as vs_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Empty set means no violations
	result == set()
}

# Test for regex match on VirtualService
test_vs_regex {
	vs_review := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.istio.io",
				"kind": "VirtualService",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "test",
					"namespace": "test",
				},
				"spec": {
					"hosts": ["testing.com", "test.com"],
					"http": [{"match": [{"uri": {"regex": "^/finance/[a-f1-0](16)"}}]}],
					"tcp": [{"route": [{"destination": {"host": "finance.test.scv.cluster.local"}}]}],
					"tls": [{"match": [{"sniHosts": ["finance.test.scv.cluster.local"]}]}],
				},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/finance"},{"host": "testing.com","path":"/finance"}]`},
			"name": "test",
		},
	}}

	exemptions := [""]

	result := violation with input as vs_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Empty set means no violations
	result == set()
}

# Test for an Ingress hostname conflicting with another namespace
test_ingress_hostname_conflicts {
	existing_ingress := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "Ingress",
		"metadata": {
			"name": "red_ingress",
			"namespace": "red",
		},
		"spec": {"rules": [{
			"host": "red.test.com",
			"http": {"paths": [{
				"path": "/finance",
				"backend": {
					"serviceName": "banking",
					"servicePort": 443,
				},
			}]},
		}]},
	}

	existing_ingress2 := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "Ingress",
		"metadata": {
			"name": "red_ingress",
			"namespace": "red",
		},
		"spec": {"rules": [{
			"host": "notred.test.com",
			"http": {"paths": [{
				"path": "/finance",
				"backend": {
					"serviceName": "banking",
					"servicePort": 443,
				},
			}]},
		}]},
	}

	existing_vs := {
		"apiVersion": "networking.istio.io/v1beta1",
		"kind": "VirtualService",
		"metadata": {
			"name": "red_vs",
			"namespace": "red",
		},
		"spec": {
			"gateways": ["ingress-general-system/general-istio-ingress-gateway-https"],
			"hosts": ["red.test.com"],
			"http": [{
				"match": [{
					"authority": {"exact": "red.test.com"},
					"uri": {"prefix": "/"},
				}],
				"route": [{
					"destination": {
						"host": "red.red.svc.cluster.local",
						"port": {"number": 9080},
					},
					"weight": 100,
				}],
			}],
		},
	}

	existing_vs2 := {
		"apiVersion": "networking.istio.io/v1beta1",
		"kind": "VirtualService",
		"metadata": {
			"name": "red_vs2",
			"namespace": "red",
		},
		"spec": {
			"gateways": ["ingress-general-system/general-istio-ingress-gateway-https"],
			"hosts": ["red.test.com", "redder.test.com"],
			"http": [{
				"match": [{
					"authority": {"exact": "red.test.com"},
					"uri": {"prefix": "/"},
				}],
				"route": [{
					"destination": {
						"host": "red.red.svc.cluster.local",
						"port": {"number": 9080},
					},
					"weight": 100,
				}],
			}],
		},
	}

	new_ingress := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.k8s.io",
				"kind": "Ingress",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "red-ingress-from-blue",
					"namespace": "blue",
				},
				"spec": {"rules": [{
					"host": "red.test.com",
					"http": {"paths": [{
						"pathType": "ImplementationSpecific",
						"backend": {"service": {
							"name": "red-from-blue",
							"port": {"number": 443},
						}},
					}]},
				}]},
			},
		},
	}

	exemptions := ["*.test.com"]

	result := violation with input as new_ingress with data.inventory.namespace.red["networking.k8s.io/v1"].Ingress.red_ingress as existing_ingress with data.inventory.namespace.red["networking.k8s.io/v1"].Ingress.red_ingress2 as existing_ingress2 with data.inventory.namespace.red["networking.istio.io/v1beta1"].VirtualService.red_vs as existing_vs with data.inventory.namespace.red["networking.istio.io/v1beta1"].VirtualService.red_vs2 as existing_vs2 with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Duplicate hostname violation expected
	print(result)
	count(result) > 0
}

# Test for permitted Ingress hostname conflict with another namespace
test_allowed_ingress_hostname_conflicts {
	existing_ingress := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "Ingress",
		"metadata": {
			"name": "red_ingress",
			"namespace": "red",
		},
		"spec": {"rules": [{
			"host": "red.test.com",
			"http": {"paths": [{
				"path": "/finance",
				"backend": {
					"serviceName": "banking",
					"servicePort": 443,
				},
			}]},
		}]},
	}

	existing_ingress2 := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "Ingress",
		"metadata": {
			"name": "red_ingress",
			"namespace": "red",
		},
		"spec": {"rules": [{
			"host": "notred.test.com",
			"http": {"paths": [{
				"path": "/finance",
				"backend": {
					"serviceName": "banking",
					"servicePort": 443,
				},
			}]},
		}]},
	}

	existing_vs := {
		"apiVersion": "networking.istio.io/v1beta1",
		"kind": "VirtualService",
		"metadata": {
			"name": "red_vs",
			"namespace": "red",
		},
		"spec": {
			"gateways": ["ingress-general-system/general-istio-ingress-gateway-https"],
			"hosts": ["red.test.com"],
			"http": [{
				"match": [{
					"authority": {"exact": "red.test.com"},
					"uri": {"prefix": "/"},
				}],
				"route": [{
					"destination": {
						"host": "red.red.svc.cluster.local",
						"port": {"number": 9080},
					},
					"weight": 100,
				}],
			}],
		},
	}

	existing_vs2 := {
		"apiVersion": "networking.istio.io/v1beta1",
		"kind": "VirtualService",
		"metadata": {
			"name": "red_vs2",
			"namespace": "red",
		},
		"spec": {
			"gateways": ["ingress-general-system/general-istio-ingress-gateway-https"],
			"hosts": ["red.test.com", "redder.test.com"],
			"http": [{
				"match": [{
					"authority": {"exact": "red.test.com"},
					"uri": {"prefix": "/"},
				}],
				"route": [{
					"destination": {
						"host": "red.red.svc.cluster.local",
						"port": {"number": 9080},
					},
					"weight": 100,
				}],
			}],
		},
	}

	new_ingress := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.k8s.io",
				"kind": "Ingress",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "red-ingress-from-blue",
					"namespace": "blue",
				},
				"spec": {"rules": [{
					"host": "red.test.com",
					"http": {"paths": [{
						"path": "/finance",
						"backend": {
							"serviceName": "banking",
							"servicePort": 443,
						},
					}]},
				}]},
			},
		},
	}

	exemptions := ["*.test.com"]

	namespaces := {"blue": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "red.test.com","path":"/finance"}]`},
			"name": "blue",
		},
	}}

	result := violation with input as new_ingress with data.inventory.namespace.red["networking.k8s.io/v1"].Ingress.red_ingress as existing_ingress with data.inventory.namespace.red["networking.k8s.io/v1"].Ingress.red_ingress2 as existing_ingress2 with data.inventory.namespace.red["networking.istio.io/v1beta1"].VirtualService.red_vs as existing_vs with data.inventory.namespace.red["networking.istio.io/v1beta1"].VirtualService.red_vs2 as existing_vs2 with input.parameters.exemptions as exemptions with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Empty set means no violations
	result == set()
}

# Test for a VirtualService hostname conflicting with another namespace
test_vs_hostname_conflicts {
	existing_ingress := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "Ingress",
		"metadata": {
			"name": "red_ingress",
			"namespace": "red",
		},
		"spec": {"rules": [{
			"host": "red.test.com",
			"http": {"paths": [{
				"path": "/finance",
				"backend": {
					"serviceName": "banking",
					"servicePort": 443,
				},
			}]},
		}]},
	}

	existing_ingress2 := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "Ingress",
		"metadata": {
			"name": "red_ingress",
			"namespace": "red",
		},
		"spec": {"rules": [{
			"host": "notred.test.com",
			"http": {"paths": [{
				"path": "/finance",
				"backend": {
					"serviceName": "banking",
					"servicePort": 443,
				},
			}]},
		}]},
	}

	existing_vs := {
		"apiVersion": "networking.istio.io/v1beta1",
		"kind": "VirtualService",
		"metadata": {
			"name": "red_vs",
			"namespace": "red",
		},
		"spec": {
			"gateways": ["ingress-general-system/general-istio-ingress-gateway-https"],
			"hosts": ["red.test.com"],
			"http": [{
				"match": [{
					"authority": {"exact": "red.test.com"},
					"uri": {"prefix": "/"},
				}],
				"route": [{
					"destination": {
						"host": "red.red.svc.cluster.local",
						"port": {"number": 9080},
					},
					"weight": 100,
				}],
			}],
		},
	}

	existing_vs2 := {
		"apiVersion": "networking.istio.io/v1beta1",
		"kind": "VirtualService",
		"metadata": {
			"name": "red_vs2",
			"namespace": "red",
		},
		"spec": {
			"gateways": ["ingress-general-system/general-istio-ingress-gateway-https"],
			"hosts": ["red.test.com"],
			"http": [{
				"match": [{
					"authority": {"exact": "red.test.com"},
					"uri": {"prefix": "/"},
				}],
				"route": [{
					"destination": {
						"host": "red.red.svc.cluster.local",
						"port": {"number": 9080},
					},
					"weight": 100,
				}],
			}],
		},
	}

	new_vs := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.istio.io",
				"kind": "VirtualService",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "red-vs-from-blue",
					"namespace": "blue",
				},
				"spec": {
					"hosts": ["blue.test.com", "red.test.com"],
					"http": [{"match": [{"uri": {"prefix": "/finance"}}, {"uri": {"exact": "/finance"}}, {"uri": {"regex": "^/finance"}}]}],
					"tcp": [{"route": [{"destination": {"host": "red.red.scv.cluster.local"}}]}],
					"tls": [{"match": [{"sniHosts": ["red.red.scv.cluster.local"]}]}],
				},
			},
		},
	}

	exemptions := ["*.test.com"]

	result := violation with input as new_vs with data.inventory.namespace.red["networking.k8s.io/v1"].Ingress.red_ingress as existing_ingress with data.inventory.namespace.red["networking.k8s.io/v1"].Ingress.red_ingress2 as existing_ingress2 with data.inventory.namespace.red["networking.istio.io/v1beta1"].VirtualService.red_vs as existing_vs with data.inventory.namespace.red["networking.istio.io/v1beta1"].VirtualService.red_vs2 as existing_vs2 with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Duplicate hostname violation expected
	print(result)
	count(result) > 0
}

# Test for permitted VirtualService hostname conflict with another namespace
test_allowed_vs_hostname_conflicts {
	existing_ingress := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "Ingress",
		"metadata": {
			"name": "red_ingress",
			"namespace": "red",
		},
		"spec": {"rules": [{
			"host": "red.test.com",
			"http": {"paths": [{
				"path": "/finance",
				"backend": {
					"serviceName": "banking",
					"servicePort": 443,
				},
			}]},
		}]},
	}

	existing_ingress2 := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "Ingress",
		"metadata": {
			"name": "red_ingress",
			"namespace": "red",
		},
		"spec": {"rules": [{
			"host": "notred.test.com",
			"http": {"paths": [{
				"path": "/finance",
				"backend": {
					"serviceName": "banking",
					"servicePort": 443,
				},
			}]},
		}]},
	}

	existing_vs := {
		"apiVersion": "networking.istio.io/v1beta1",
		"kind": "VirtualService",
		"metadata": {
			"name": "red_vs",
			"namespace": "red",
		},
		"spec": {
			"gateways": ["ingress-general-system/general-istio-ingress-gateway-https"],
			"hosts": ["red.test.com"],
			"http": [{
				"match": [{
					"authority": {"exact": "red.test.com"},
					"uri": {"prefix": "/"},
				}],
				"route": [{
					"destination": {
						"host": "red.red.svc.cluster.local",
						"port": {"number": 9080},
					},
					"weight": 100,
				}],
			}],
		},
	}

	existing_vs2 := {
		"apiVersion": "networking.istio.io/v1beta1",
		"kind": "VirtualService",
		"metadata": {
			"name": "red_vs2",
			"namespace": "red",
		},
		"spec": {
			"gateways": ["ingress-general-system/general-istio-ingress-gateway-https"],
			"hosts": ["red.test.com"],
			"http": [{
				"match": [{
					"authority": {"exact": "red.test.com"},
					"uri": {"prefix": "/"},
				}],
				"route": [{
					"destination": {
						"host": "red.red.svc.cluster.local",
						"port": {"number": 9080},
					},
					"weight": 100,
				}],
			}],
		},
	}

	new_vs := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.istio.io",
				"kind": "VirtualService",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "red-vs-from-blue",
					"namespace": "blue",
				},
				"spec": {
					"hosts": ["blue.test.com", "red.test.com"],
					"http": [{"match": [{"uri": {"prefix": "/finance"}}, {"uri": {"exact": "/finance"}}, {"uri": {"regex": "^/finance"}}]}],
					"tcp": [{"route": [{"destination": {"host": "red.red.scv.cluster.local"}}]}],
					"tls": [{"match": [{"sniHosts": ["red.red.scv.cluster.local"]}]}],
				},
			},
		},
	}

	namespaces := {"blue": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "red.test.com","path":"/finance"}]`},
			"name": "blue",
		},
	}}

	exemptions := ["*.test.com"]

	result := violation with input as new_vs with data.inventory.namespace.red["networking.k8s.io/v1"].Ingress.red_ingress as existing_ingress with data.inventory.namespace.red["networking.k8s.io/v1"].Ingress.red_ingress2 as existing_ingress2 with data.inventory.namespace.red["networking.istio.io/v1beta1"].VirtualService.red_vs as existing_vs with data.inventory.namespace.red["networking.istio.io/v1beta1"].VirtualService.red_vs2 as existing_vs2 with input.parameters.exemptions as exemptions with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Empty set means no violations
	result == set()
}

# Test for Ingress with unallowed host and no path
test_ingress_unallowed_host_no_path {
	ingress := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.k8s.io",
				"kind": "Ingress",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "unallowed-ingress",
					"namespace": "test",
				},
				"spec": {"rules": [{
					"host": "unallowedtest.com",
					"http": {"paths": [{
						"pathType": "ImplementationSpecific",
						"backend": {"service": {
							"name": "unallowedtest",
							"port": {"number": 443},
						}},
					}]},
				}]},
			},
		},
	}

	result := violation with input as ingress with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Violation expected
	print(result)
	count(result) > 0
}

# Test for VirtualService with unallowed host and no path
test_vs_unallowed_host_no_path {
	vs := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.istio.io",
				"kind": "VirtualService",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "unallowed-vs",
					"namespace": "test",
				},
				"spec": {
					"hosts": ["nope.com", "nah.com", "ok.test.com"],
					"http": [{"route": [{"destination": {"host": "myservice"}}]}],
				},
			},
		},
	}

	exemptions := ["*.test.com"]

	result := violation with input as vs with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Violation expected
	print(result)
	count(result) > 0
}

# Test for an allowed VS which sets a host but not matches on the path.
# `test.com` is effectively the same as `test.com/` since the `/` is a seperator in our prefix strategy.
test_vs_allowed_no_path {
	vs_review := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.istio.io",
				"kind": "VirtualService",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "test",
					"namespace": "test",
				},
				"spec": {
					"hosts": ["test.com"],
					"http": [],
				},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/"}]`},
			"name": "test",
		},
	}}

	exemptions := [""]

	result := violation with input as vs_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Empty set means no violations
	result == set()
}

# Test for an allowed Ingress which sets a host but not matches on the path.
# `test.com` is effectively the same as `test.com/` since the `/` is a seperator in our prefix strategy.
test_ingress_allowed_no_path {
	ingress_review := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.k8s.io",
				"kind": "Ingress",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "test",
					"namespace": "test",
				},
				"spec": {"rules": [{
					"host": "test.com",
					"http": {"paths": [{
						"pathType": "ImplementationSpecific",
						"backend": {"service": {
							"name": "test",
							"port": {"number": 443},
						}},
					}]},
				}]},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/"}]`},
			"name": "test",
		},
	}}

	exemptions := [""]

	result := violation with input as ingress_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Empty set means no violations
	result == set()
}

test_ingress_not_allowed_no_host {
	ingress_review := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.k8s.io",
				"kind": "Ingress",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "test",
					"namespace": "test",
				},
				"spec": {"rules": [{
					"http": {"paths": [{
						"path": "/test",
						"pathType": "ImplementationSpecific",
						"backend": {"service": {
							"name": "test",
							"port": {"number": 443},
						}},
					}]},
				}]},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/"}]`},
			"name": "test",
		},
	}}

	exemptions := [""]

	result := violation with input as ingress_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Violation expected
	print(result)
	count(result) > 0
}

test_ingress_allowed_no_host {
	ingress_review := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "networking.k8s.io",
				"kind": "Ingress",
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice",
			},
			"object": {
				"metadata": {
					"name": "test",
					"namespace": "test",
				},
				"spec": {"rules": [{
					"http": {"paths": [{
						"path": "/test",
						"pathType": "ImplementationSpecific",
						"backend": {"service": {
							"name": "test",
							"port": {"number": 443},
						}},
					}]},
				}]},
			},
		},
	}

	namespaces := {"test": {
		"apiVersion": "v1",
		"kind": "Namespace",
		"metadata": {
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "*","path":"/"}]`},
			"name": "test",
		},
	}}

	exemptions := [""]

	result := violation with input as ingress_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"

	# Empty set means no violations
	result == set()
}