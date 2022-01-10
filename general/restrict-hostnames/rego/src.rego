package restricthostnames

# Annotation which contains JSON information about exempted Hosts and Paths
# JSON structure is as follows:
# array(
#   object(
#     host: string,
#     path: string
#   )
# )
annotation := "ingress.statcan.gc.ca/allowed-hosts"

# Allowed hosts scraped from the above annotation.
allowedHosts := hosts {
	json.is_valid(data.inventory.cluster.v1.Namespace[input.review.object.metadata.namespace].metadata.annotations[annotation])
	hosts := normalize_hosts(json.unmarshal(data.inventory.cluster.v1.Namespace[input.review.object.metadata.namespace].metadata.annotations[annotation]))
}

# Normalizes the objects for easier logic by lowercasing the path.
normalize_hosts(hosts) = normalized_hosts {
	normalized_hosts := [host |
		current_host_object := hosts[_]
		host := {"host": current_host_object.host, "path": lower(current_host_object.path)}
	]
}

identical(obj, review) {
	obj.metadata.namespace == review.object.metadata.namespace
	obj.metadata.name == review.object.metadata.name
}

# Exemptions for hosts passed in via the configuration of the Policy
is_exempt(host) {
	exemption := input.parameters.exemptions[_]
	glob.match(exemption, [], host)
}

# Exemptions for hosts within the namespace
is_exempt(host) {
	glob.match(concat(".", ["*", input.review.object.metadata.namespace, "svc**"]), [], host)
}

# Host and path is permitted
is_allowed(host, path) {
	allowedHost := allowedHosts[_]

	host == allowedHost.host
	startswith(lower(path), allowedHost.path)
}

# Host and path is permitted for VirtualServices regex match
# Regex must start with an allowed path in the form of "^$PATH*"
is_allowed_regex(host, path) {
	allowedHost := allowedHosts[_]

	host == allowedHost.host
	startswith(path, concat("", ["^", allowedHost.path]))
}

# Determines ifa host and path combination is invalid and returns a concatenated response
is_invalid(host, path) = invalid {
	# Check if the hostname is exempt
	not is_exempt(host)

	# Check if the hostname is allowed
	not is_allowed(host, path)

	invalid := concat("", [host, path])
}

# Ingress
violation[{"msg": msg}] {
	input.review.kind.kind == "Ingress"
	input.review.kind.group == "networking.k8s.io"

	# Gather all invalid host and path combinations
	invalid_hostpaths := {hostpath |
		rule := input.review.object.spec.rules[_]
		host := rule.host
		path := rule.http.paths[_].path

		hostpath := is_invalid(host, path)
	}

	count(invalid_hostpaths) > 0

	msg := sprintf("hostpaths in the ingress are not valid for this namespace: %v", [invalid_hostpaths])
}

# Virtual Service
violation[{"msg": msg}] {
	input.review.kind.kind == "VirtualService"
	input.review.kind.group == "networking.istio.io"

	# Gather all invalid host and path combinations
	invalid_hostpaths := {hostpath |
		paths := ({path | path := input.review.object.spec.http[_].match[_].uri.exact} | {path | path := input.review.object.spec.http[_].match[_].uri.prefix}) | {path | path := input.review.object.spec.http[_].match[_].uri.regex}

		path := paths[_]
		host := input.review.object.spec.hosts[_]

		hostpath := is_invalid(host, path)
	}
	
	count(invalid_hostpaths) > 0

	msg := sprintf("hostpaths in the virtualservice are not valid for this namespace: %v", [invalid_hostpaths])
}
