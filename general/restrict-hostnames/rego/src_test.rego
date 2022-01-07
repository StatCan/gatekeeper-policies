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

# Test for any path under a host
test_ingress_fail {
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
	count(result) == 1
}

# Test for any path under a host
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

	# 2 messages, one for each path in the paths
	print(result)
	count(result) == 2
}
