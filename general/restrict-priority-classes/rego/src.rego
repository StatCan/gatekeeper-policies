package restrictpriorityclasses

# Create a set of the priority class names
priority_class_names := {name | name := input.parameters.priorityClassNames[_]}

violation[{"msg": msg}] {
	priority_class_name := input.review.object.spec.priorityClassName

	# Check intersection of sets.
	# If empty, is in violation.
	priority_class_names & {priority_class_name} == set()

	msg := sprintf("pod %s is using an unapproved priority class %q. Available priority classes are %v.", [input.review.object.metadata.name, priority_class_name, priority_class_names])
}
