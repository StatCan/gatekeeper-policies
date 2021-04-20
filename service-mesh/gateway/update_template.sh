#!/bin/bash
# Upates the template.yaml files rego from the rego file
REGO=$(cat securedgateways.rego) yq eval -i '.spec.targets[0].rego = strenv(REGO)' template.yaml
