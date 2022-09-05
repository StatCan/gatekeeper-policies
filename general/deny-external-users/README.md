## Internal Users Policy

Applies to RoleBindings and AuthorizationPolicy objects

Checks labels set in Profile to allow RoleBindings and AuthorizationPolicy objects to be created

### Label Set in Profile

`state.aaw.statcan.gc.ca/has-sas-notebook-feature: "true"` --> deny

`state.aaw.statcan.gc.ca/has-sas-notebook-feature: "false"` --> allow

If the label is not set in the Profile, the fallthrough/default is to allow.

### Internal Users

If the User is an internal employee (name/email ends with an accepted domain), the RoleBinding and AuthorizationPolicy will be created without checking the label.

## Test Cases (in examples folder)

alice:
- external user
- `state.aaw.statcan.gc.ca/has-sas-notebook-feature: "true"`
- **denied**

bob:
- external user
- `state.aaw.statcan.gc.ca/has-sas-notebook-feature: "false"`
- **allowed**

jo:
- external user
- label is not present in Profile
- **allowed**

sam:
- internal user
- `state.aaw.statcan.gc.ca/has-sas-notebook-feature: "true"`
- **allowed** (doesn't matter if the label is present or what it's set to)
