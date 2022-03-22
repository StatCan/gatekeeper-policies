## Internal Users Policy

Applies to RoleBindings and AuthorizationPolicy objects

Checks labels set in Profile to allow RoleBindings and AuthorizationPolicy objects to be created

### Label Set in Profile

`feature.aaw.statcan.gc.ca/employee-only: "true"` --> deny

`state.aaw.statcan.gc.ca/employee-only-features: "true"` --> deny

`feature.aaw.statcan.gc.ca/employee-only: "false"` --> allow

`state.aaw.statcan.gc.ca/employee-only-features: "false"` --> allow

If the label is not set in the Profile, the fallthrough/default is to allow.

### Internal Users

If the User is an internal employee (name/email ends with an accepted domain), the RoleBinding and AuthorizationPolicy will be created without checking the label.

## Test Cases (in examples folder)

alice:
- external user
- `feature.aaw.statcan.gc.ca/employee-only: "true"`
- **denied**

bob:
- external user
- `feature.aaw.statcan.gc.ca/employee-only: "false"`
- **allowed**

jo:
- external user
- label is not present in Profile
- **allowed**

sam:
- internal user
- `feature.aaw.statcan.gc.ca/employee-only: "true"`
- **allowed** (doesn't matter if the label is present or what it's set to)
