package denyemployeeonlyfeatures

sasLabel := "state.aaw.statcan.gc.ca/exists-non-sas-notebook-user"
sasImagePrefix := "k8scc01covidacr.azurecr.io/sas:"

ns := input.review.object.metadata.namespace
profile := data.inventory.cluster["kubeflow.org/v1"]["Profile"][ns]
profileLabel :=  profile.metadata.labels[sasLabel]

# Pod Object
violation[{"msg": msg}] {
    input.review.object.kind == "Pod"
    container := input.review.object.spec.containers[_]
    existsSasContainerAndLabelViolation(container, profileLabel)
    msg := sprintf("Pod has state.aaw.statcan.gc.ca/exists-non-sas-notebook-user=%v and container uses a SAS image %v", [profileLabel, container.image])
}

# Notebook Object
violation[{"msg": msg}] {
    input.review.object.kind == "Notebook"
    container := input.review.object.spec.template.spec.containers[_]
    existsSasContainerAndLabelViolation(container, profileLabel)
    msg := sprintf("Notebook has state.aaw.statcan.gc.ca/exists-non-sas-notebook-user=%v and container uses a SAS image %v", [profileLabel, container.image])
}

existsSasContainerAndLabelViolation(container, profileLabel) {
    profileLabel == "true"
    startswith(container.image, sasImagePrefix)
}