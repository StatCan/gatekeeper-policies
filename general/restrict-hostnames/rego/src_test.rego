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

# Test for any path under a host
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
							"path": "/finANCE",
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
			"annotations": {"ingress.statcan.gc.ca/allowed-hosts": `[{"host": "test.com","path":"/FINance"}]`},
			"name": "test",
		},
	}}

	result := violation with input as ingress with data.inventory.cluster.v1.Namespace as namespaces

	# If result set is empty, no violations
	result == set()
}

# Test for any path under a host
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

	result := violation with input as ingress with data.inventory.cluster.v1.Namespace as namespaces

	# If result set is empty, no violations
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

	result := violation with input as ingress with data.inventory.cluster.v1.Namespace as namespaces

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

	result := violation with input as ingress with data.inventory.cluster.v1.Namespace as namespaces

	# result with entry means there was a violation
	print(result)
	count(result) > 0
}

# Test for Ingress and Namespace without annotation.
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

	result := violation with input as ingress with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions

	#Empty set means no violations
	result == set()
}

# Test for Ingress and Namespace without annotation.
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

	result := violation with input as vs_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions

	#Empty set means no violations
	result == set()
}

# Test for Ingress and Namespace without annotation.
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

	result := violation with input as vs_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions

	count(result) > 0
	print(result)
}

# Test for Ingress and Namespace without annotation.
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

	result := violation with input as vs_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions

	#Empty set means no violations
	result == set()
}

# Test for Ingress and Namespace without annotation.
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

	result := violation with input as vs_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions

	count(result) > 0
	print(result)
}

# Test for Ingress and Namespace without annotation.
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

	result := violation with input as vs_review with data.inventory.cluster.v1.Namespace as namespaces with input.parameters.exemptions as exemptions

	#Empty set means no violations
	result == set()
}
