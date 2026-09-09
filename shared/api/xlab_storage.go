package api

import "errors"

// XlabRootAuthority is the controller's complete contract-3 storage identity.
type XlabRootAuthority struct {
	IDMap       XlabRootIDMap `json:"id_map"`
	Version     int           `json:"version"`
	Revision    uint64        `json:"revision"`
	InstanceID  string        `json:"instance_id"`
	VolumeID    string        `json:"volume_id"`
	OwnerID     string        `json:"owner_id"`
	Epoch       uint64        `json:"epoch"`
	Generation  uint64        `json:"generation"`
	ProjectID   uint32        `json:"project_id"`
	QuotaBytes  int64         `json:"quota_bytes"`
	QuotaInodes int64         `json:"quota_inodes"`
	Phase       string        `json:"phase"`
}

// XlabRootInspectionRequest selects the exact authority and local pool binding.
type XlabRootInspectionRequest struct {
	Authority XlabRootAuthority `json:"authority"`
	Pool      string            `json:"pool"`
	Source    string            `json:"source"`
}

// XlabRootInspection reports observed completion and configured quota readback.
// It is not proof of EDQUOT enforcement or storage-backend qualification.
type XlabRootInspection struct {
	XlabRootInspectionRequest
	BootID       string `json:"boot_id"`
	RootFID      string `json:"root_fid"`
	Ready        bool   `json:"ready"`
	IDMapMatches bool   `json:"id_map_matches"`
}

// XlabRootIDMap is stable across host transfers and root generation replacement.
// The platform reserves a full isolated range and directly maps its owner's ID.
type XlabRootIDMap struct {
	Base   uint32 `json:"base"`
	UserID uint32 `json:"user_id"`
}

func (m XlabRootIDMap) Validate() error {
	if m.Base < 65536 || uint64(m.Base)+65536 > 4294967295 || m.UserID < 10000 || m.UserID >= 65536 {
		return errors.New("Root requires a reserved isolated ID range and a platform user ID")
	}
	return nil
}

// XlabRootReleaseRequest selects one committed source-release authority exactly.
// It never authorizes a timeout takeover, data deletion or a different generation.
type XlabRootReleaseRequest struct {
	VolumeID   string `json:"volume_id"`
	InstanceID string `json:"instance_id"`
	OwnerID    string `json:"owner_id"`
	Epoch      uint64 `json:"epoch"`
	Generation uint64 `json:"generation"`
	Revision   uint64 `json:"revision"`
}

// XlabRootRelease is observed by the daemon after quiescence and ordinary unmount.
type XlabRootRelease struct {
	XlabRootReleaseRequest
	RootFID         string            `json:"root_fid"`
	Metadata        *XlabRootMetadata `json:"metadata"`
	BootID          string            `json:"boot_id"`
	InstanceStopped bool              `json:"instance_stopped"`
	RestartBlocked  bool              `json:"restart_blocked"`
	RootDetached    bool              `json:"root_detached"`
}
