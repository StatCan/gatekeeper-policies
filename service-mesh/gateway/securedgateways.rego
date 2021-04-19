package securedgateways

# Ensure HTTP is only for redirect
violation[{"msg": msg}] {
	gateway := input.review.object
	server := gateway.spec.servers[_]

	is_http(server.port.protocol)
	server.tls.httpsRedirect == false
	msg := "HTTP servers can only be used for HTTPS redirect."
}

is_http(protocol) {
	protocol == "HTTP"
}

is_http(protocol) {
	protocol == "HTTP2"
}

# Ensure HTTPS follows minimum TLS settings
violation[{"msg": msg}] {
	gateway := input.review.object
	server := gateway.spec.servers[_]

	server.port.protocol == "HTTPS"
	not contains(input.parameters.minTLSVersions, server.tls.minProtocolVersion)
	msg := sprintf("minProtocolVersion for HTTPS must be one of the following: %v", [input.parameters.minTLSVersions])
}

# Ensure HTTPS follows maximum TLS settings
violation[{"msg": msg}] {
	gateway := input.review.object
	server := gateway.spec.servers[_]

	server.port.protocol == "HTTPS"
	not contains(input.parameters.maxTLSVersions, server.tls.maxProtocolVersion)
	msg := sprintf("maxProtocolVersion for HTTPS must be one of the following: %v", [input.parameters.maxTLSVersions])
}

# Ensure only approved CipherSuites are used.
violation[{"msg": msg}] {
	gateway := input.review.object
	server := gateway.spec.servers[_]

	server.port.protocol == "HTTPS"
	approvedCipherSuites := {cs | cs = input.parameters.approvedCipherSuites[_]}
	usedCipherSuites := {cs | cs = server.tls.cipherSuites[_]}
	count(usedCipherSuites - approvedCipherSuites) != 0
	msg := sprintf("Only the following CipherSuites may be used: %v", [approvedCipherSuites])
}

contains(array, string) {
	array[_] == string
}
