## Employee-Only Features Policy

Applies to Pod objects

Checks `state.aaw.statcan.gc.ca/non-employee-users` set in Pod and container image to allow/deny Pod object to be created

### Label Set in Profile

`state.aaw.statcan.gc.ca/non-employee-users: "true"` and SAS image --> deny

`state.aaw.statcan.gc.ca/non-employee-users: "true"` and non-SAS image --> allow

`state.aaw.statcan.gc.ca/non-employee-users: "false"`´ --> allow 

If the label is not set in the Pod, the fallthrough/default is to allow.

### SAS Images

If the container image starts with `k8scc01covidacr.azurecr.io/sas:`, it is considered a SAS image and the label will have to be set to `false` to create the Pod object.

## Test Cases (in examples folder)

alice:
- `state.aaw.statcan.gc.ca/non-employee-users: "true"`
- SAS image
- **denied**

bob:
- `state.aaw.statcan.gc.ca/non-employee-users: "true"`
- non-SAS image
- **allowed**

tom:
- `state.aaw.statcan.gc.ca/non-employee-users: "false"`
- SAS image
- **allowed** (doesn't matter what the image is)
