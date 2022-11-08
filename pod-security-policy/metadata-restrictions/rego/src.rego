package metadatarestrictions

same(a, b) {
    a == b
}

# Allowed values
violation[{"msg": msg}] {
    restriction := input.parameters[kind][_]
    input.review.object.metadata[kind][restriction.key]
    count(restriction.allowedValues) == 0
    count(restriction.allowedRegex) == 0
    msg := sprintf("%s %q not allowed", [kind, restriction.key])
}

violation[{"msg": msg}] {
    val := input.review.object.metadata[kind][key]
    restriction := input.parameters[kind][_]
    restriction.key == key
    count(array.concat(restriction.allowedValues,restriction.allowedRegex)) > 0
    foundValues := [foundValues | foundValues = restriction.allowedValues[_] == val]
    foundRegex := [foundRegex | foundRegex = regex.match(restriction.allowedRegex[regex], val)]
    not any(array.concat(foundValues,foundRegex))

    msg := sprintf("%s %q value %q not allowed, allowed values/regex: %v", [kind, key, val, array.concat(restriction.allowedValues,restriction.allowedRegex)])
}

# Immutability
violation[{"msg": msg}] {
    input.review.operation == "UPDATE"

    restriction := input.parameters[kind][_]
    restriction.immutable
    newval := object.get(input.review.object.metadata[kind], restriction.key, restriction.fallback)
    oldval := object.get(input.review.oldObject.metadata[kind], restriction.key, restriction.fallback)

    not same(newval, oldval)

    msg := sprintf("label %q is immutable: %q -> %q not permitted", [restriction.key, oldval, newval])
}