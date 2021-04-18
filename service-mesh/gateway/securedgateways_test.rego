package securedgateways

parameters = {
    "approvedCipherSuites": ["TLS_AES_256_GCM_SHA384","TLS_AES_128_GCM_SHA256","ECDHE-RSA-AES256-GCM-SHA384","ECDHE-RSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384","ECDHE-ECDSA-AES128-GCM-SHA256"],
    "maxTLSVersions": ["TLSV1_2"],
    "minTLSVersions": ["TLSV1_2"]
}

gatewayPass = {
    "apiVersion": "networking.istio.io/v1beta1",
    "kind": "Gateway",
    "metadata": {
        "name": "gateway",
        "namespace": "istio-system"
    },
    "spec": {
        "selector": {
            "app": "istio-ingressgateway",
            "istio": "ingressgateway"
        },
        "servers": [
            {
                "hosts": [
                    "*"
                ],
                "port": {
                    "name": "http",
                    "number": 80,
                    "protocol": "HTTP2"
                },
                "tls": {
                    "httpsRedirect": true
                }
            },
            {
                "hosts": [
                    "*"
                ],
                "port": {
                    "name": "https-default",
                    "number": 443,
                    "protocol": "HTTPS"
                },
                "tls": {
                    "cipherSuites": [
                        "TLS_AES_256_GCM_SHA384",
                        "TLS_AES_128_GCM_SHA256",
                        "ECDHE-RSA-AES256-GCM-SHA384",
                        "ECDHE-RSA-AES128-GCM-SHA256"
                    ],
                    "maxProtocolVersion": "TLSV1_2",
                    "minProtocolVersion": "TLSV1_2"
                }
            }
        ]
    }
}

gatewayFailHttpRedirect = {
    "apiVersion": "networking.istio.io/v1beta1",
    "kind": "Gateway",
    "metadata": {
        "name": "gateway",
        "namespace": "istio-system"
    },
    "spec": {
        "selector": {
            "app": "istio-ingressgateway",
            "istio": "ingressgateway"
        },
        "servers": [
            {
                "hosts": [
                    "*"
                ],
                "port": {
                    "name": "http",
                    "number": 80,
                    "protocol": "HTTP2"
                },
                "tls": {
                    "httpsRedirect": false
                }
            },
            {
                "hosts": [
                    "*"
                ],
                "port": {
                    "name": "https-default",
                    "number": 443,
                    "protocol": "HTTPS"
                },
                "tls": {
                    "cipherSuites": [
                        "TLS_AES_256_GCM_SHA384",
                        "TLS_AES_128_GCM_SHA256",
                        "ECDHE-RSA-AES256-GCM-SHA384",
                        "ECDHE-RSA-AES128-GCM-SHA256"
                    ],
                    "maxProtocolVersion": "TLSV1_2",
                    "minProtocolVersion": "TLSV1_2"
                }
            }
        ]
    }
}

gatewayFailTLSConfig = {
    "apiVersion": "networking.istio.io/v1beta1",
    "kind": "Gateway",
    "metadata": {
        "name": "gateway",
        "namespace": "istio-system"
    },
    "spec": {
        "selector": {
            "app": "istio-ingressgateway",
            "istio": "ingressgateway"
        },
        "servers": [
            {
                "hosts": [
                    "*"
                ],
                "port": {
                    "name": "http",
                    "number": 80,
                    "protocol": "HTTP2"
                },
                "tls": {
                    "httpsRedirect": true
                }
            },
            {
                "hosts": [
                    "*"
                ],
                "port": {
                    "name": "https-default",
                    "number": 443,
                    "protocol": "HTTPS"
                },
                "tls": {
                    "cipherSuites": [
                        "TLS_AES_256_GCM_SHA384",
                        "TLS_AES_128_GCM_SHA256",
                        "ECDHE-RSA-AES256-GCM-SHA384",
                        "ECDHE-RSA-AES128-GCM-SHA256",
                        "ECDHE-RSA-AES128-GCM"
                    ],
                    "maxProtocolVersion": "TLSV1_1",
                    "minProtocolVersion": "TLSV1_3"
                }
            }
        ]
    }
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
    count(result) == 3
}
