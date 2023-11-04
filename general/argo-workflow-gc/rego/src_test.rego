package argoworkflowgc

# Ensures that prefix allowance works correctly.
test_workflow_no_gc_fail {
	input := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
    "review": {
      "kind": {
        "group": "argoproj.io/v1alpha1",
        "kind": "Workflow",
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
        "spec": {
          "entrypoint": "whalesay",
          "templates": [
            {
              "name": "whalesay",
              "container": {
                "image": "docker/whalesay",
                "command": ["cowsay"],
                "args": ["hello world"],
              },
            }
          ],
        },
			},
		},
	}

	result := violation with input as input with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"
  count(result) > 0
}

test_cron_workflow_no_gc_fail {
	input := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
    "review": {
      "kind": {
        "group": "argoproj.io/v1alpha1",
        "kind": "CronWorkflow",
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
        "spec": {
          "schedule": "* * * * *",
          "timezone": "America/Los_Angeles",
          "startingDeadlineSeconds": 0,
          "concurrencyPolicy": "Replace",
          "successfulJobsHistoryLimit": 4,
          "failedJobsHistoryLimit": 4,
          "suspend": false,
          "workflowSpec": {
            "entrypoint": "whalesay",
            "templates": [
              {
                "name": "whalesay",
                "container": {
                  "image": "docker/whalesay",
                  "command": ["cowsay"],
                  "args": ["hello world"],
                },
              },
            ],
          },
        },
			},
		},
	}

	result := violation with input as input with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"
  count(result) > 0
}

# Ensures that prefix allowance works correctly.
test_workflow_set_podgc_success {
	input := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
    "review": {
      "kind": {
        "group": "argoproj.io/v1alpha1",
        "kind": "Workflow",
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
        "spec": {
          "entrypoint": "whalesay",
          "podGC": {
            "strategy": "OnPodSuccess",
          },
          "templates": [
            {
              "name": "whalesay",
              "container": {
                "image": "docker/whalesay",
                "command": ["cowsay"],
                "args": ["hello world"],
              },
            }
          ],
        },
			},
		},
	}

	result := violation with input as input with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"
	result == set()
}

test_cron_workflow_set_podgc_success {
	input := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
    "review": {
      "kind": {
        "group": "argoproj.io/v1alpha1",
        "kind": "CronWorkflow",
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
        "spec": {
          "schedule": "* * * * *",
          "timezone": "America/Los_Angeles",
          "startingDeadlineSeconds": 0,
          "concurrencyPolicy": "Replace",
          "successfulJobsHistoryLimit": 4,
          "failedJobsHistoryLimit": 4,
          "suspend": false,
          "workflowSpec": {
            "entrypoint": "whalesay",
            "podGC": {
              "strategy": "OnPodSuccess",
            },
            "templates": [
              {
                "name": "whalesay",
                "container": {
                  "image": "docker/whalesay",
                  "command": ["cowsay"],
                  "args": ["hello world"],
                },
              },
            ],
          },
        },
			},
		},
	}

	result := violation with input as input with input.parameters.errorMsgAdditionalDetails as "(Additional details placeholder)"
  result == set()
}
