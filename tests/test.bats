# Copyright 2021 Open Policy Agent
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/usr/bin/env bats

load helpers

WAIT_TIME=300
SLEEP_TIME=5

@test "testing constraint templates" {
  for policy in ./*/*/ ; do
    if [ -d "$policy" ]; then
      local policy_group=$(basename "$(dirname "$policy")")
      local template_name=$(basename "$policy")
      local kind=$(yq e .metadata.name "$policy"/template.yaml)

      if [[ "$policy_group" != "general" ]] &&
         [[ "$policy_group" != "pod-security-policy" ]] &&
         [[ "$policy_group" != "service-mesh" ]]
      then
        continue
      fi

      echo "running integration test against policy group: $policy_group, constraint template: $template_name"
      wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl apply -k $policy"

      for example in "$policy"/examples/; do
        local name=$(yq e .metadata.name "$example"/constraint.yaml )

        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl apply -f ${example}/constraint.yaml"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "constraint_enforced $kind $name"

        for allowed in "$example"/allowed.yaml; do
          if [[ -e "$allowed" ]]; then
            run kubectl apply -f "$allowed"
            assert_match 'created' "$output"
            assert_success
            kubectl delete --ignore-not-found -f "$allowed"
          fi
        done

        for disallowed in "$example"/disallowed.yaml; do
          if [[ -e "$disallowed" ]]; then
            run kubectl apply -f "$disallowed"
            assert_match 'denied the request' "${output}"
            assert_failure
            kubectl delete --ignore-not-found -f "$disallowed"
          fi
        done

        kubectl delete -f "$example"/constraint.yaml
      done

      kubectl delete -k "$policy"
    fi
  done
}
