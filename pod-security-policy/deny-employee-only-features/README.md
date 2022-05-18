## Employee-Only Features Policy

Applies to Pod and Notebook objects

Checks `state.aaw.statcan.gc.ca/non-employee-users` label in Profile and the container image to allow/deny Pod and Notebook objects to be created

### Label Set in Pod and Notebook

`state.aaw.statcan.gc.ca/non-employee-users: "true"` and SAS image --> deny

`state.aaw.statcan.gc.ca/non-employee-users: "true"` and non-SAS image --> allow

`state.aaw.statcan.gc.ca/non-employee-users: "false"`´ --> allow 

If the label is not set in the Profile, the fallthrough/default is to allow.

### SAS Images

If the container image starts with `k8scc01covidacr.azurecr.io/sas:`, it is considered a SAS image and the label in the Profile will have to be set to `false` to create the Pod and Notebook objects.

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
