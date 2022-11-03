package metadatarestrictions

# WID 6 digits
violation[{"msg": msg}] {
	wid := input.review.object.metadata.labels["finance.statcan.gc.ca/workload-id"]
	output := regex.match("^[0-9]{6}$", wid)
	not output
	msg := sprintf("workload-id needs to be six digits; you have %s", [wid])
}
