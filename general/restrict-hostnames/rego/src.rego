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

is_exempt(host) {
	exemption := input.parameters.exemptions[_]
	glob.match(exemption, [], host)
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

# Ingress
violation[{"msg": msg}] {
	input.review.kind.kind == "Ingress"
	input.review.kind.group == "networking.k8s.io"

	rule := input.review.object.spec.rules[_]
	host := rule.host
	path := rule.http.paths[_].path

	# Check if the hostname is exempt
	not is_exempt(host)

	# Check if the hostname is allowed
	not is_allowed(host, path)

	msg := sprintf("ingress host <%v> and path <%v> is not allowed for this namespace", [host, path])
}

# Virtual Service
# (regex)
violation[{"msg": msg}] {
	input.review.kind.kind == "VirtualService"
	input.review.kind.group == "networking.istio.io"

	host := input.review.object.spec.hosts[_]
	path := input.review.object.spec.http[_].match[_].uri.regex

	# Check if the hostname is exempt
	not is_exempt(host)

	# Check if the hostname is allowed
	not is_allowed_regex(host, path)

	msg := sprintf("virtualservice host <%v> and path <%v> is not allowed for this namespace", [host, path])
}

# Common validation for VirtualServices
virtual_service(path) = msg {
	input.review.kind.kind == "VirtualService"
	input.review.kind.group == "networking.istio.io"

	host := input.review.object.spec.hosts[_]

	# Check if the hostname is exempt
	not is_exempt(host)

	# Check if the hostname is allowed
	not is_allowed(host, path)

	msg := sprintf("virtualservice host <%v> and path <%v> is not allowed for this namespace", [host, path])
}

# (prefix)
violation[{"msg": msg}] {
	path := input.review.object.spec.http[_].match[_].uri.prefix

	msg := virtual_service(path)
}

# (exact)
violation[{"msg": msg}] {
	path := input.review.object.spec.http[_].match[_].uri.exact

	msg := virtual_service(path)
}
