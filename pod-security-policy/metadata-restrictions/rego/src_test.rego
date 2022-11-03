package metadatarestrictions

# Ensures that a non six-digit workload-ID flags a violation
test_5_digit_wid {
	request := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "test",
				"kind": "Namespace",
				"version": "v1beta1"
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice"
			},
			"object": {"metadata": {
				"name": "ns-test",
				"labels": {
					"finance.statcan.gc.ca/workload-id": "1234",
					"project.statcan.gc.ca/financial-responsibility-centre": "test"
				}
			}}
		}
	}

	results := violation with input as request

	count(results) == 1
}

# Ensures that a  six-digit workload-ID **does not** flag a violation
test_6_digit_wid {
	request := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"review": {
			"kind": {
				"group": "test",
				"kind": "Namespace",
				"version": "v1beta1"
			},
			"operation": "CREATE",
			"userInfo": {
				"groups": null,
				"username": "alice"
			},
			"object": {"metadata": {
				"name": "ns-test",
				"labels": {
					"finance.statcan.gc.ca/workload-id": "123456",
					"project.statcan.gc.ca/financial-responsibility-centre": "test"
				}
			}}
		}
	}

	results := violation with input as request

	count(results) == 0
}
