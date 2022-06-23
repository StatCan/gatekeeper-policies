package securedgateways

parameters = {
	"approvedCipherSuites": ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256"],
	"maxTLSVersions": ["TLSV1_2"],
	"minTLSVersions": ["TLSV1_2"],
	"tlsModes": ["SIMPLE"],
}

gatewayPass = {
	"apiVersion": "networking.istio.io/v1beta1",
	"kind": "Gateway",
	"metadata": {
		"name": "gateway",
		"namespace": "istio-system",
	},
	"spec": {
		"selector": {
			"app": "istio-ingressgateway",
			"istio": "ingressgateway",
		},
		"servers": [
			{
				"hosts": ["*"],
				"port": {
					"name": "http",
					"number": 80,
					"protocol": "HTTP2",
				},
				"tls": {"httpsRedirect": true},
			},
			{
				"hosts": ["*"],
				"port": {
					"name": "https-default",
					"number": 443,
					"protocol": "HTTPS",
				},
				"tls": {
					"cipherSuites": [
						"TLS_AES_256_GCM_SHA384",
						"TLS_AES_128_GCM_SHA256",
						"ECDHE-RSA-AES256-GCM-SHA384",
						"ECDHE-RSA-AES128-GCM-SHA256",
					],
					"maxProtocolVersion": "TLSV1_2",
					"minProtocolVersion": "TLSV1_2",
					"mode": "SIMPLE",
				},
			},
		],
	},
}

gatewayFailHttpRedirect = {
	"apiVersion": "networking.istio.io/v1beta1",
	"kind": "Gateway",
	"metadata": {
		"name": "gateway",
		"namespace": "istio-system",
	},
	"spec": {
		"selector": {
			"app": "istio-ingressgateway",
			"istio": "ingressgateway",
		},
		"servers": [{
			"hosts": ["*"],
			"port": {
				"name": "http",
				"number": 80,
				"protocol": "HTTP2",
			},
			"tls": {"httpsRedirect": false},
		}],
	},
}

gatewayFailTLSConfig = {
	"apiVersion": "networking.istio.io/v1beta1",
	"kind": "Gateway",
	"metadata": {
		"name": "gateway",
		"namespace": "istio-system",
	},
	"spec": {
		"selector": {
			"app": "istio-ingressgateway",
			"istio": "ingressgateway",
		},
		"servers": [
			{
				"hosts": ["*"],
				"port": {
					"name": "http",
					"number": 80,
					"protocol": "HTTP2",
				},
				"tls": {"httpsRedirect": true},
			},
			{
				"hosts": ["*"],
				"port": {
					"name": "https-default",
					"number": 443,
					"protocol": "HTTPS",
				},
				"tls": {
					"cipherSuites": [
						"TLS_AES_256_GCM_SHA384",
						"TLS_AES_128_GCM_SHA256",
						"ECDHE-RSA-AES256-GCM-SHA384",
						"ECDHE-RSA-AES128-GCM-SHA256",
						"ECDHE-RSA-AES128-GCM",
					],
					"maxProtocolVersion": "TLSV1_1",
					"minProtocolVersion": "TLSV1_3",
					"mode": "MUTUAL",
				},
			},
		],
	},
}

gatewayTLSNotSet = {
	"apiVersion": "networking.istio.io/v1beta1",
	"kind": "Gateway",
	"metadata": {
		"name": "gateway",
		"namespace": "istio-system",
	},
	"spec": {
		"selector": {
			"app": "istio-ingressgateway",
			"istio": "ingressgateway",
		},
		"servers": [{
			"hosts": ["*"],
			"port": {
				"name": "https-default",
				"number": 443,
				"protocol": "HTTPS",
			},
			"tls": {
				"cipherSuites": [
					"TLS_AES_256_GCM_SHA384",
					"TLS_AES_128_GCM_SHA256",
					"ECDHE-RSA-AES256-GCM-SHA384",
					"ECDHE-RSA-AES128-GCM-SHA256",
				],
				"mode": "SIMPLE",
			},
		}],
	},
}

gatewayNoCiphers = {
	"apiVersion": "networking.istio.io/v1beta1",
	"kind": "Gateway",
	"metadata": {
		"name": "gateway",
		"namespace": "istio-system",
	},
	"spec": {
		"selector": {
			"app": "istio-ingressgateway",
			"istio": "ingressgateway",
		},
		"servers": [
			{
				"hosts": ["*"],
				"port": {
					"name": "http",
					"number": 80,
					"protocol": "HTTP2",
				},
				"tls": {"httpsRedirect": true},
			},
			{
				"hosts": ["*"],
				"port": {
					"name": "https-default",
					"number": 443,
					"protocol": "HTTPS",
				},
				"tls": {
					"cipherSuites": [],
					"maxProtocolVersion": "TLSV1_2",
					"minProtocolVersion": "TLSV1_2",
					"mode": "SIMPLE",
				},
			},
		],
	},
}

gatewayTLSModeNotSet = {
	"apiVersion": "networking.istio.io/v1beta1",
	"kind": "Gateway",
	"metadata": {
		"name": "gateway",
		"namespace": "istio-system",
	},
	"spec": {
		"selector": {
			"app": "istio-ingressgateway",
			"istio": "ingressgateway",
		},
		"servers": [
			{
				"hosts": ["*"],
				"port": {
					"name": "http",
					"number": 80,
					"protocol": "HTTP2",
				},
				"tls": {"httpsRedirect": true},
			},
			{
				"hosts": ["*"],
				"port": {
					"name": "https-default",
					"number": 443,
					"protocol": "HTTPS",
				},
				"tls": {
					"cipherSuites": ["ECDHE-RSA-AES256-GCM-SHA384"],
					"maxProtocolVersion": "TLSV1_2",
					"minProtocolVersion": "TLSV1_2",
				},
			},
		],
	},
}

test_pass {
	result := violation with input.parameters as parameters with input.review.object as gatewayPass
	trace(sprintf("%v", [result]))
	count(result) == 0
}

test_fail_http_redirect {
	result := violation with input.parameters as parameters with input.review.object as gatewayFailHttpRedirect
	trace(sprintf("%v", [result]))
	count(result) == 1
}

test_fail_tls_config {
	result := violation with input.parameters as parameters with input.review.object as gatewayFailTLSConfig
	trace(sprintf("%v", [result]))
	count(result) == 4
}

test_fail_tls_not_set {
	result := violation with input.parameters as parameters with input.review.object as gatewayTLSNotSet
	trace(sprintf("%v", [result]))
	count(result) == 2
}

test_fail_ciphers_not_set {
	result := violation with input.parameters as parameters with input.review.object as gatewayNoCiphers
	trace(sprintf("%v", [result]))
	count(result) == 1
}

test_fail_tls_mode_not_set {
	result := violation with input.parameters as parameters with input.review.object as gatewayTLSModeNotSet
	trace(sprintf("%v", [result]))
	count(result) == 1
}
