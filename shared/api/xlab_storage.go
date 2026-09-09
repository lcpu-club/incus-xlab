package api

import (
	"errors"
	"github.com/google/uuid"
)

// XlabRootAuthority is the controller's complete contract-4 storage identity.
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

// XlabRootIDMap pins a common system map and one account lease for the root's
// lifetime. Peer people identities are never included in this namespace.
type XlabRootIDMap struct {
	Base       uint32 `json:"base"`
	LeaseID    string `json:"lease_id"`
	GuestUID   uint32 `json:"guest_uid"`
	GuestGID   uint32 `json:"guest_gid"`
	BackendUID uint32 `json:"backend_uid"`
	BackendGID uint32 `json:"backend_gid"`
}

func (m XlabRootIDMap) Validate() error {
	lease, err := uuid.Parse(m.LeaseID)
	if err != nil || lease == uuid.Nil || lease.String() != m.LeaseID ||
		m.Base != 100000000 || m.GuestUID < 10000 || m.GuestUID >= 50000 ||
		m.GuestGID != m.GuestUID || m.BackendUID != 100100000+m.GuestUID-10000 ||
		m.BackendGID != m.BackendUID {
		return errors.New("Root requires the provisioned common system map and a canonical account lease")
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
