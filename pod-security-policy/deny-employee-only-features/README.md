## Employee-Only Features Policy

Applies to Pod and Notebook objects

Checks `state.aaw.statcan.gc.ca/exists-non-sas-notebook-user` label set in both Pod and Notebook objects and container image to allow/deny Pod and Notebook objects to be created

### Label Set in Pod and Notebook

`state.aaw.statcan.gc.ca/exists-non-sas-notebook-user: "true"` and SAS image --> deny

`state.aaw.statcan.gc.ca/exists-non-sas-notebook-user: "true"` and non-SAS image --> allow

`state.aaw.statcan.gc.ca/exists-non-sas-notebook-user: "false"`´ --> allow

If the label is not set in the Pod and/or the Notebook, the fallthrough/default is to allow.

### SAS Images

If the container image starts with `k8scc01covidacr.azurecr.io/sas:`, it is considered a SAS image and the label will have to be set to `false` to create the Pod and Notebook objects.

## Test Cases (in examples folder)

alice:
- `state.aaw.statcan.gc.ca/exists-non-sas-notebook-user: "true"`
- SAS image
- **denied**

bob:
- `state.aaw.statcan.gc.ca/exists-non-sas-notebook-user: "true"`
- non-SAS image
- **allowed**

tom:
- `state.aaw.statcan.gc.ca/exists-non-sas-notebook-user: "false"`
- SAS image
- **allowed** (doesn't matter what the image is)