package storage

import (
	"errors"
	"os"

	"github.com/lxc/incus/v6/internal/server/instance"
	"github.com/lxc/incus/v6/internal/server/instance/instancetype"
	"github.com/lxc/incus/v6/internal/server/response"
	"github.com/lxc/incus/v6/internal/server/storage/drivers"
	"github.com/lxc/incus/v6/shared/api"
)

// PrepareInstanceRoot creates no instance, volume, directory or mount. The
// endpoint holds the instance operation lock throughout this native preflight.
func PrepareInstanceRoot(pool Pool, req api.XlabRootPrepareRequest) (*api.XlabRootPreparation, error) {
	b, ok := pool.(*backend)
	if !ok || b.driver.Info().Name != "lustre" {
		return nil, errors.New("Preparation requires Lustre")
	}
	vol, err := rootAdoptVolume(b, api.XlabRootAdoptRequest{Target: req.XlabRootInspectionRequest})
	if err != nil {
		return nil, err
	}
	driver, ok := b.driver.(interface {
		PrepareRoot(drivers.Volume, api.XlabRootPrepareRequest, func() error) (*api.XlabRootPreparation, error)
	})
	if !ok {
		return nil, errors.New("Lustre driver lacks target preparation")
	}
	return driver.PrepareRoot(vol, req, func() error {
		_, err := instance.LoadByProjectAndName(b.state, api.ProjectDefaultName, vol.Name())
		if err == nil {
			return errors.New("Target already has local instance metadata")
		}
		if !response.IsNotFoundError(err) {
			return err
		}
		_, err = VolumeDBGet(pool, api.ProjectDefaultName, vol.Name(), drivers.VolumeTypeContainer)
		if err == nil {
			return errors.New("Target already has local root volume metadata")
		}
		if !response.IsNotFoundError(err) {
			return err
		}
		for _, path := range []string{InstancePath(instancetype.Container, api.ProjectDefaultName, vol.Name(), false), vol.MountPath()} {
			if err := rootForgetLocalParent(path); err != nil {
				return err
			}
			if _, err := os.Lstat(path); err == nil {
				return errors.New("Target still has local root paths")
			} else if !os.IsNotExist(err) {
				return err
			}
		}
		return nil
	})
}
