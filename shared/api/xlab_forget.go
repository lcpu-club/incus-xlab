package api

// XlabRootForgetRequest authorizes removal of one former owner's local metadata.
// Authority is the current attached target grant; pool/source are local bindings
// on the former host. It never authorizes physical volume destruction.
type XlabRootForgetRequest struct {
	XlabRootInspectionRequest
	FormerOwnerID string `json:"former_owner_id"`
	FormerEpoch   uint64 `json:"former_epoch"`
	RootFID       string `json:"root_fid"`
}

type XlabRootForget struct {
	XlabRootForgetRequest
	BootID            string `json:"boot_id"`
	LocalMetadataGone bool   `json:"local_metadata_gone"`
	RootRetained      bool   `json:"root_retained"`
}
