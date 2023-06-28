package restrictpriorityclasses

names := ["priority-low", "priority-high"]

test_allowed_names {
	priority_class_name := "priority-low"
	pod_name := "test-pod"

	result := violation with input.parameters.priorityClassNames as names with input.review.object.spec.priorityClassName as priority_class_name with input.review.object.metadata.name as pod_name

	# No results mean there is no violation.
	result == set()
}

test_unallowed_names {
	priority_class_name := "priority-med"
	pod_name := "test-pod"

	result := violation with input.parameters.priorityClassNames as names with input.review.object.spec.priorityClassName as priority_class_name with input.review.object.metadata.name as pod_name

	# A result means there is a violation.
	result != set()
}

test_no_names {
	priority_class_name := ""
	pod_name := "test-pod"

	result := violation with input.parameters.priorityClassNames as names with input.review.object.spec.priorityClassName as priority_class_name with input.review.object.metadata.name as pod_name

	# A result means there is a violation.
	result != set()
}
