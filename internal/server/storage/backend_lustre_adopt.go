package storage

import (
	"errors"
	"github.com/google/uuid"
	"os"
	"strconv"
	"strings"

	backupConfig "github.com/lxc/incus/v6/internal/server/backup/config"
	"github.com/lxc/incus/v6/internal/server/instance"
	"github.com/lxc/incus/v6/internal/server/instance/instancetype"
	"github.com/lxc/incus/v6/internal/server/storage/drivers"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/revert"
)

func rootAdoptVolume(pool *backend, req api.XlabRootAdoptRequest) (drivers.Volume, error) {
	a := req.Target.Authority
	id, err := uuid.Parse(a.InstanceID)
	if err != nil || id == uuid.Nil || id.String() != a.InstanceID {
		return drivers.Volume{}, errors.New("Invalid instance UUID")
	}
	return pool.GetVolume(drivers.VolumeTypeContainer, drivers.ContentTypeFS, "tc-"+strings.ReplaceAll(a.InstanceID, "-", "")[:12], map[string]string{
		"lustre.volume_id": a.VolumeID, "lustre.owner_epoch": strconv.FormatUint(a.Epoch, 10), "lustre.generation": strconv.FormatUint(a.Generation, 10), "size": strconv.FormatInt(a.QuotaBytes, 10),
	}), nil
}

func LockRootAdoption(pool Pool, req api.XlabRootAdoptRequest) (func(), error) {
	b, ok := pool.(*backend)
	if !ok || b.driver.Info().Name != "lustre" {
		return nil, errors.New("Adoption requires Lustre")
	}
	driver, ok := b.driver.(interface {
		LockRootAdopt(drivers.Volume, api.XlabRootAdoptRequest) (func(), error)
	})
	if !ok {
		return nil, errors.New("Lustre driver lacks metadata adoption")
	}
	vol, err := rootAdoptVolume(b, req)
	if err != nil {
		return nil, err
	}
	return driver.LockRootAdopt(vol, req)
}

// AdoptInstanceRoot restores only local DB rows, empty mount paths and symlinks.
// ImportInstance has no filler/template/backup-file write; its rollback deletes
// only the local rows and links it created. No generic DeleteInstance is called.
func AdoptInstanceRoot(pool Pool, inst instance.Instance, req api.XlabRootAdoptRequest) (revert.Hook, error) {
	b, ok := pool.(*backend)
	if !ok || b.driver.Info().Name != "lustre" || inst.Type() != instancetype.Container {
		return nil, errors.New("Adoption requires a Lustre container")
	}
	path := InstancePath(inst.Type(), inst.Project().Name, inst.Name(), false)
	if _, err := os.Lstat(path); err == nil {
		return nil, errors.New("Adoption cannot replace an existing instance path")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	vol, err := rootAdoptVolume(b, req)
	if err != nil {
		return nil, err
	}
	return b.ImportInstance(inst, &backupConfig.Config{Volume: &api.StorageVolume{StorageVolumePut: api.StorageVolumePut{Config: vol.Config()}}}, nil)
}
