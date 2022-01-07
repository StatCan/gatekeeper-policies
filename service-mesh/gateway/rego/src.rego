package securedgateways

# Ensure HTTP is only for redirect
violation[{"msg": msg}] {
	gateway := input.review.object
	server := gateway.spec.servers[_]

	is_http(server.port.protocol)
	not server.tls.httpsRedirect
	msg := "HTTP servers can only be used for HTTPS redirect. Please ensure that httpsRedirect is set to true in the TLS settings."
}

is_http(protocol) {
	protocol == "HTTP"
}

is_http(protocol) {
	protocol == "HTTP2"
}

# Ensure minimum TLS is set on HTTPS
violation[{"msg": msg}] {
	gateway := input.review.object
	server := gateway.spec.servers[_]

	server.port.protocol == "HTTPS"
	not server.tls.minProtocolVersion
	msg := tls_protocol_violation_msg("minProtocolVersion", input.parameters.minTLSVersions)
}

# Ensure HTTPS follows minimum TLS settings
violation[{"msg": msg}] {
	gateway := input.review.object
	server := gateway.spec.servers[_]

	server.port.protocol == "HTTPS"
	not contains(input.parameters.minTLSVersions, server.tls.minProtocolVersion)
	msg := tls_protocol_violation_msg("minProtocolVersion", input.parameters.minTLSVersions)
}

# Ensure maximum TLS is set on HTTPS
violation[{"msg": msg}] {
	gateway := input.review.object
	server := gateway.spec.servers[_]

	server.port.protocol == "HTTPS"
	not server.tls.maxProtocolVersion
	msg := tls_protocol_violation_msg("maxProtocolVersion", input.parameters.maxTLSVersions)
}

# Ensure HTTPS follows maximum TLS settings
violation[{"msg": msg}] {
	gateway := input.review.object
	server := gateway.spec.servers[_]

	server.port.protocol == "HTTPS"
	not contains(input.parameters.maxTLSVersions, server.tls.maxProtocolVersion)
	msg := tls_protocol_violation_msg("maxProtocolVersion", input.parameters.maxTLSVersions)
}

tls_protocol_violation_msg(parameterName, options) = msg {
	msg := sprintf("TLS %v for HTTPS must be set to one of the following: %v", [parameterName, options])
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

# Ensure CipherSuites are set and not empty
violation[{"msg": msg}] {
	gateway := input.review.object
	server := gateway.spec.servers[_]

	server.port.protocol == "HTTPS"
	cipherSuites := [cs | cs = server.tls.cipherSuites[_]]
	count(cipherSuites) == 0
	msg := sprintf("CipherSuites must be defined from the following: %v", [input.parameters.approvedCipherSuites])
}

violation[{"msg": msg}] {
	gateway := input.review.object
	server := gateway.spec.servers[_]

	server.port.protocol == "HTTPS"
	not server.tls.mode
	msg := sprintf("TLS mode must be set to one of the following: %v", [input.parameters.tlsModes])
}

violation[{"msg": msg}] {
	gateway := input.review.object
	server := gateway.spec.servers[_]

	server.port.protocol == "HTTPS"
	not contains(input.parameters.tlsModes, server.tls.mode)
	msg := sprintf("TLS mode must be set to one of the following: %v", [input.parameters.tlsModes])
}

contains(array, string) {
	array[_] == string
}
