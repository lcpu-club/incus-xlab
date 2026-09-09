package api

// XlabRootPrepareRequest reads the current source's attached root through the
// target's local pool. This grants no ownership and creates no local metadata.
type XlabRootPrepareRequest struct {
	XlabRootInspectionRequest
	OperationID   string `json:"operation_id"`
	TargetOwnerID string `json:"target_owner_id"`
	Architecture  string `json:"architecture"`
	RootFID       string `json:"root_fid"`
}

type XlabRootPreparation struct {
	XlabRootPrepareRequest
	BootID              string `json:"boot_id"`
	LocalMetadataAbsent bool   `json:"local_metadata_absent"`
	IDMapDelegated      bool   `json:"id_map_delegated"`
	Ready               bool   `json:"ready"`
}
