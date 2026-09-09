package drivers

import (
	"errors"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/idmap"
)

// LockRootAdopt checks physical identity before any local metadata is created and
// holds the controller authority stable until adoption/rollback completes.
func (d *lustre) LockRootAdopt(vol Volume, req api.XlabRootAdoptRequest) (func(), error) {
	a, r := req.Target.Authority, req.Release
	if a.Phase != "creating" || a.Epoch <= 1 || r.Epoch != a.Epoch-1 || r.VolumeID != a.VolumeID || r.InstanceID != a.InstanceID || r.Generation != a.Generation || r.OwnerID == a.OwnerID || r.Revision == 0 || r.Revision >= a.Revision || !r.InstanceStopped || !r.RestartBlocked || !r.RootDetached || lustreCanonicalUUID(r.BootID) != nil || lustreCanonicalUUID(r.OwnerID) != nil || r.Metadata == nil {
		return nil, errors.New("Adoption requires the preceding owner's exact stopped release")
	}
	if err := r.Metadata.Validate(); err != nil {
		return nil, err
	}
	unlock, err := d.lockAuthority(vol)
	if err != nil {
		return nil, err
	}
	observed, err := d.InspectRoot(vol, req.Target, func(want *idmap.Set) error {
		for _, key := range []string{"volatile.last_state.idmap", "volatile.idmap.next"} {
			actual, err := idmap.NewSetFromJSON(r.Metadata.Config[key])
			if err != nil {
				return err
			}
			if !want.Equals(actual) {
				return errors.New("Source metadata differs from persistent root identity")
			}
		}
		return nil
	})
	if err == nil && observed.RootFID != r.RootFID {
		err = errors.New("Target root FID differs from released source")
	}
	if err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}
