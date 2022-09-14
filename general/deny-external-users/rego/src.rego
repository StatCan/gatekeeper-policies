package denyexternalusers

# RoleBinding Object
violation[{"msg": msg}] {
    obj := input.review.object
    obj.kind == "RoleBinding"
    email := obj.subjects[_].name
    contains(email, "@")
    not isEmployee(email)
    # If the non-employee is in the exception list, then allow
    count([exceptionCase | exceptionCase := input.parameters.sasNotebookExceptions[_]; exceptionCase == email]) == 0
    ns := obj.metadata.namespace
    profile := data.inventory.cluster["kubeflow.org/v1"]["Profile"][ns]
    profileLabel := input.parameters.labels[_]
    profile.metadata.labels[profileLabel] == "true"
    msg := sprintf("Profile %v has %v=%v", [ns, profileLabel, profile.metadata.labels[profileLabel]])
}

# AuthorizationPolicy Object
violation[{"msg": msg}] {
    obj := input.review.object
    obj.kind == "AuthorizationPolicy"
    email := obj.spec.rules[_]["when"][_]["values"][_]
    contains(email, "@")
    not isEmployee(email)
    # If the non-employee is in the exception list, then allow
    count([exceptionCase | exceptionCase := input.parameters.sasNotebookExceptions[_]; exceptionCase == email]) == 0
    ns := obj.metadata.namespace
    profile := data.inventory.cluster["kubeflow.org/v1"]["Profile"][ns]
    profileLabel := input.parameters.labels[_]
    profile.metadata.labels[profileLabel] == "true"
    msg := sprintf("Profile %v has %v=%v", [ns, profileLabel, profile.metadata.labels[profileLabel]])
}

# Ensure only non-internal employees are checked
isEmployee(email) {
    endswith(email, concat("@", [input.parameters.employeeDomains[_]]))
}

# TODO: should refactor this in the future to get the exception list from configmap directly.
# isEmployee(email) {
#     # exceptionList := yaml.unmarshal(data.inventory.namespace["statcan-system"]["v1"]["configmap"]["non-employee-exceptions"]["non-employee-exceptions.yaml"])
#     # If the namespace has purpose "system", then this policy does not apply.
#     count([exceptionCase | exceptionCase := input.parameters.exceptionList[_]; exceptionCase == email]) > 0
# }
