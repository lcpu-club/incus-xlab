package storage

import (
	"errors"
	"github.com/lxc/incus/v6/internal/server/instance"
	"github.com/lxc/incus/v6/internal/server/project"
	"github.com/lxc/incus/v6/internal/server/storage/drivers"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/idmap"
	"github.com/lxc/incus/v6/shared/osarch"
	"github.com/lxc/incus/v6/shared/util"
)

// InitialRootIDMap is available before the local volume DB row exists. Identity
// still comes from the shared creating authority selected by initial.* keys.
func InitialRootIDMap(pool Pool, inst instance.Instance) (*idmap.Set, error) {
	b, ok := pool.(*backend)
	if !ok || b.driver.Info().Name != "lustre" {
		return nil, errors.New("Initial root map requires Lustre")
	}
	config := map[string]string{}
	if err := b.applyInstanceRootDiskInitialValues(inst, config); err != nil {
		return nil, err
	}
	typ, err := InstanceTypeToVolumeType(inst.Type())
	if err != nil {
		return nil, err
	}
	vol := b.GetVolume(typ, InstanceContentType(inst), project.Instance(inst.Project().Name, inst.Name()), config)
	return vol.ImageUnpackIDMap()
}

func completedRootIDMap(pool Pool, vol drivers.Volume) (*idmap.Set, error) {
	driver, ok := pool.Driver().(interface {
		RootDiskIDMap(drivers.Volume, bool) (*idmap.Set, error)
	})
	if !ok {
		return nil, errors.New("Lustre driver lacks completed disk identity")
	}
	return driver.RootDiskIDMap(vol, true)
}

func (b *backend) recordCreatedRootIDMap(inst instance.Instance, vol drivers.Volume) error {
	if b.driver.Info().Name != "lustre" {
		return nil
	}
	disk, err := completedRootIDMap(b, vol)
	if err != nil {
		return err
	}
	container, ok := inst.(instance.Container)
	if !ok {
		return errors.New("Lustre root requires a container")
	}
	next, err := container.NextIdmap()
	if err != nil {
		return err
	}
	if !disk.Equals(next) {
		return errors.New("Created root map differs from initial container identity")
	}
	encoded, err := disk.ToJSON()
	if err != nil {
		return err
	}
	return inst.VolatileSet(map[string]string{"volatile.last_state.idmap": encoded})
}

func validateRootRuntimeIDMap(pool Pool, inst instance.Instance, vol drivers.Volume) error {
	want, err := completedRootIDMap(pool, vol)
	if err != nil {
		return err
	}
	return checkRootRuntimeIDMap(inst, want)
}

func checkRootRuntimeIDMap(inst instance.Instance, want *idmap.Set) error {
	container, ok := inst.(instance.Container)
	if !ok {
		return errors.New("Lustre root requires a container")
	}
	next, err := container.NextIdmap()
	if err != nil {
		return err
	}
	disk, err := container.DiskIdmap()
	if err != nil {
		return err
	}
	if !want.Equals(next) || !want.Equals(disk) {
		return errors.New("Lustre disk/next identity must match its persistent root map; recursive shifting is forbidden")
	}
	return nil
}

func lustreInstanceVolume(pool Pool, inst instance.Instance) (drivers.Volume, error) {
	b, ok := pool.(*backend)
	if !ok || b.driver.Info().Name != "lustre" || inst.ID() < 0 {
		return drivers.Volume{}, errors.New("Lustre release requires an allocated local instance")
	}
	typ, err := InstanceTypeToVolumeType(inst.Type())
	if err != nil {
		return drivers.Volume{}, err
	}
	dbVol, err := VolumeDBGet(pool, inst.Project().Name, inst.Name(), typ)
	if err != nil {
		return drivers.Volume{}, err
	}
	vol := b.GetVolume(typ, InstanceContentType(inst), project.Instance(inst.Project().Name, inst.Name()), dbVol.Config)
	if err := b.applyInstanceRootDiskOverrides(inst, &vol); err != nil {
		return drivers.Volume{}, err
	}
	return vol, nil
}

// LockInstanceStart covers all startup paths, including stateful restore, until
// Start returns. Non-Lustre drivers retain their existing behavior.
func LockInstanceStart(pool Pool, inst instance.Instance) (func(), error) {
	if pool.Driver().Info().Name != "lustre" {
		return func() {}, nil
	}
	vol, err := lustreInstanceVolume(pool, inst)
	if err != nil {
		return nil, err
	}
	driver, ok := pool.Driver().(interface {
		LockRootStart(drivers.Volume) (func(), error)
	})
	if !ok {
		return nil, errors.New("Lustre driver lacks startup authority locking")
	}
	unlock, err := driver.LockRootStart(vol)
	if err != nil {
		return nil, err
	}
	if err := validateRootRuntimeIDMap(pool, inst, vol); err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

// ReleaseInstanceRoot holds the driver's control lock while the caller quiesces
// file access and the driver syncs and unmounts the exact root.
func ReleaseInstanceRoot(pool Pool, inst instance.Instance, req api.XlabRootReleaseRequest, quiesce func() error) (*api.XlabRootRelease, error) {
	vol, err := lustreInstanceVolume(pool, inst)
	if err != nil {
		return nil, err
	}
	driver, ok := pool.Driver().(interface {
		ReleaseRoot(drivers.Volume, api.XlabRootReleaseRequest, func() error, func(*idmap.Set) (*api.XlabRootMetadata, error)) (*api.XlabRootRelease, error)
	})
	if !ok {
		return nil, errors.New("Lustre driver lacks root release")
	}
	return driver.ReleaseRoot(vol, req, quiesce, func(want *idmap.Set) (*api.XlabRootMetadata, error) {
		b := pool.(*backend)
		fresh, err := instance.LoadByProjectAndName(b.state, inst.Project().Name, inst.Name())
		if err != nil {
			return nil, err
		}
		if fresh.IsRunning() || fresh.IsEphemeral() || fresh.IsSnapshot() || fresh.IsStateful() || len(fresh.Profiles()) != 0 {
			return nil, errors.New("Shared-root handoff requires a stopped, persistent, stateless container without profiles")
		}
		if err := checkRootRuntimeIDMap(fresh, want); err != nil {
			return nil, err
		}
		arch, err := osarch.ArchitectureName(fresh.Architecture())
		if err != nil {
			return nil, err
		}
		metadata := &api.XlabRootMetadata{Version: 1, Architecture: arch, CreatedAt: fresh.CreationDate(), LastUsedAt: fresh.LastUsedDate(), Description: fresh.Description(), Config: util.CloneMap(fresh.LocalConfig()), Devices: fresh.LocalDevices().CloneNative()}
		if metadata.Config["user.tc.id"] != req.InstanceID || metadata.Config["user.tc.managed"] != "true" {
			return nil, errors.New("Source metadata is not the allocated managed instance")
		}
		return metadata, metadata.Validate()
	})
}

// InspectInstanceRoot verifies physical completion using the fork driver, while
// comparing its persisted map against this local instance's disk/next maps.
func InspectInstanceRoot(pool Pool, inst instance.Instance, req api.XlabRootInspectionRequest) (*api.XlabRootInspection, error) {
	vol, err := lustreInstanceVolume(pool, inst)
	if err != nil {
		return nil, err
	}
	driver, ok := pool.Driver().(interface {
		InspectRoot(drivers.Volume, api.XlabRootInspectionRequest, func(*idmap.Set) error) (*api.XlabRootInspection, error)
	})
	if !ok {
		return nil, errors.New("Lustre driver lacks root inspection")
	}
	return driver.InspectRoot(vol, req, func(want *idmap.Set) error { return checkRootRuntimeIDMap(inst, want) })
}
