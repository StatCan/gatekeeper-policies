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
is_allowed(host, path) {
	allowedHost := allowedHosts[_]

	host == allowedHost.host
	startswith(path, concat("", ["^", allowedHost.path]))
}

# Determines if a host and path combination is invalid and returns a concatenated response.
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

# Hostname conflict with other namespace Ingress(es) and hostpath not allowed
violation[{"msg": msg}] {
	kind := input.review.kind.kind
	re_match("^(Ingress|VirtualService)$", kind)
	re_match("^(networking.k8s.io|networking.istio.io)$", input.review.kind.group)

	hosts := {host | host := input.review.object.spec.rules[_].host} | {host | host := input.review.object.spec.hosts[_]}
	host := hosts[_]
	paths := {path | path := input.review.object.spec.rules[_].http.paths[_].path} | ({path | path := input.review.object.spec.http[_].match[_].uri.exact} | {path | path := input.review.object.spec.http[_].match[_].uri.prefix}) | {path | path := input.review.object.spec.http[_].match[_].uri.regex}
	path := paths[_]

	not is_allowed(host, path)

	ingress_conflicts := {output | conflict := data.inventory.namespace[other_namespace]["networking.k8s.io/v1"]["Ingress"][other_name]
	conflict.spec.rules[_].host == host
	conflict.metadata.namespace != input.review.object.metadata.namespace
	output := concat("/", [other_namespace, other_name])
	}

	count(ingress_conflicts) > 0
    msg := sprintf("%v hostname %v conflicts with existing Ingress(es): %v", [kind, host, ingress_conflicts])
}


# Hostname conflict with other namespace VirtualService(s) and hostpath not allowed
violation[{"msg": msg}] {
	kind := input.review.kind.kind
	re_match("^(Ingress|VirtualService)$", kind)
	re_match("^(networking.k8s.io|networking.istio.io)$", input.review.kind.group)

	hosts := {host | host := input.review.object.spec.rules[_].host} | {host | host := input.review.object.spec.hosts[_]}
	host := hosts[_]
	paths := {path | path := input.review.object.spec.rules[_].http.paths[_].path} | ({path | path := input.review.object.spec.http[_].match[_].uri.exact} | {path | path := input.review.object.spec.http[_].match[_].uri.prefix}) | {path | path := input.review.object.spec.http[_].match[_].uri.regex}
	path := paths[_]

	not is_allowed(host, path)

	vs_conflicts := {output | conflict := data.inventory.namespace[other_namespace]["networking.istio.io/v1beta1"]["VirtualService"][other_name]
	conflict.spec.hosts[_] == host
	conflict.metadata.namespace != input.review.object.metadata.namespace
	output := concat("/", [other_namespace, other_name])
	}

	count(vs_conflicts) > 0
    msg := sprintf("%v hostname %v conflicts with existing VirtualService(s): %v", [kind, host, vs_conflicts])
}