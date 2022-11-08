#!/bin/bash

for dir in */*/ ; do
  if [ -d "$dir/rego" ]; then
    if [ ! -z $(which opa) ]; then
      opa test -v $dir/rego/*
    fi
    REGO=$(cat $dir/rego/src.rego) yq eval -i '.spec.targets[0].rego = strenv(REGO)' $dir/template.yaml
  fi
done
