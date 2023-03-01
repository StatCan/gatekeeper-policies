package argoworkflowgc

violation[{"msg": msg}] {
    input.review.kind.kind == "Workflow"
    not input.review.object.spec.podGC.strategy

    msg := sprintf("podGC field is required in an Argo Workflow manifest. %s", [input.parameters.errorMsgAdditionalDetails])
}

violation[{"msg": msg}] {
    input.review.kind.kind == "CronWorkflow"
    not input.review.object.spec.workflowSpec.podGC.strategy

    msg := sprintf("podGC field is required in an Argo Workflow manifest. %s", [input.parameters.errorMsgAdditionalDetails])
}