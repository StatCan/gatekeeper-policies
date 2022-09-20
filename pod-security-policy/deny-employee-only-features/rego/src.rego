package denyemployeeonlyfeatures

sasLabel := "state.aaw.statcan.gc.ca/exists-non-sas-notebook-user"
sasImagePrefix := "k8scc01covidacr.azurecr.io/sas:"

# Pod Object
violation[{"msg": msg}] {
    input.review.object.kind == "Pod"
    ns := input.review.object.metadata.namespace
    profile := data.inventory.cluster["kubeflow.org/v1"]["Profile"][ns]
    profileLabel :=  profile.metadata.labels[sasLabel]
    profileLabel == "true"
    container := input.review.object.spec.containers[_]
    startswith(container.image, sasImagePrefix)
    msg := sprintf("Pod has state.aaw.statcan.gc.ca/exists-non-sas-notebook-user=%v and container uses a SAS image %v", [profileLabel, container.image])
}

# Notebook Object
violation[{"msg": msg}] {
    input.review.object.kind == "Notebook"
    ns := input.review.object.metadata.namespace
    profile := data.inventory.cluster["kubeflow.org/v1"]["Profile"][ns]
    profileLabel :=  profile.metadata.labels[sasLabel]
    profileLabel == "true"
    container := input.review.object.spec.template.spec.containers[_]
    startswith(container.image, sasImagePrefix)
    msg := sprintf("Notebook has state.aaw.statcan.gc.ca/exists-non-sas-notebook-user=%v and container uses a SAS image %v", [profileLabel, container.image])
}
