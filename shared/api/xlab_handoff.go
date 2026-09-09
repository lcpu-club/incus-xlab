package api

import (
	"encoding/json"
	"errors"
	"time"
)

// XlabRootMetadata is the stopped source's local instance metadata. The control
// plane retains it in the release proof and sends it to the next owner over mTLS.
// It is not an image or a backup and contains no rootfs payload.
type XlabRootMetadata struct {
	Version      int                          `json:"version"`
	Architecture string                       `json:"architecture"`
	LastUsedAt   time.Time                    `json:"last_used_at"`
	CreatedAt    time.Time                    `json:"created_at"`
	Description  string                       `json:"description"`
	Config       map[string]string            `json:"config"`
	Devices      map[string]map[string]string `json:"devices"`
}

func (m XlabRootMetadata) Validate() error {
	if m.Version != 1 || (m.Architecture != "aarch64" && m.Architecture != "x86_64") || m.CreatedAt.IsZero() || len(m.Config) == 0 || len(m.Devices) == 0 {
		return errors.New("Incomplete stopped root metadata")
	}
	for _, k := range []string{"volatile.uuid", "volatile.uuid.generation", "volatile.cloud-init.instance-id", "volatile.last_state.idmap", "volatile.idmap.next"} {
		if m.Config[k] == "" {
			return errors.New("Stopped root metadata lacks persistent instance identity")
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(raw) > 512*1024 {
		return errors.New("Stopped root metadata exceeds 512 KiB")
	}
	return nil
}

// XlabRootAdoptRequest grants only local metadata adoption of a completed root.
// Source is the controller-retained release proof, never a target's inferred stop.
type XlabRootAdoptRequest struct {
	Capacity *XlabCapacityDevice       `json:"capacity,omitempty"`
	Target   XlabRootInspectionRequest `json:"target"`
	Release  XlabRootRelease           `json:"release"`
	Bridge   string                    `json:"bridge"`
}

// XlabCapacityDevice selects the already prepared target-local required export.
// It carries no Ceph credentials and does not authorize a backend map or transfer.
type XlabCapacityDevice struct {
	VolumeID string `json:"volume_id"`
	Source   string `json:"source"`
}
