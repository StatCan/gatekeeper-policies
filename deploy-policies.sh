#!/bin/bash

# GateKeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper-constraint.yaml

# Config templates
kubectl apply -f config/

# Constraint templates
kubectl apply -f templates/

# Constraints
kubectl create -f constraints/

# Reject a request
kubectl create namespace test -o yaml

# Create a compliant namespace
cat test/namespace-with-labels.yaml
kubectl create -f test/namespace-with-labels.yaml

# Teardown
kubectl delete -f test/namespace-with-labels.yaml > /dev/null
kubectl delete -f constraints/ > /dev/null
kubectl delete -f templates/requiredlabels.yaml > /dev/null
