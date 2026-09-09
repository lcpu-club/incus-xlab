package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/lxc/incus/v6/internal/server/db"
	"github.com/lxc/incus/v6/internal/server/instance"
	"github.com/lxc/incus/v6/internal/server/instance/instancetype"
	"github.com/lxc/incus/v6/internal/server/response"
	"github.com/lxc/incus/v6/internal/server/storage/drivers"
	"github.com/lxc/incus/v6/shared/api"
)

func rootForgetName(req api.XlabRootForgetRequest) (string, error) {
	id, err := uuid.Parse(req.Authority.InstanceID)
	if err != nil || id == uuid.Nil || id.String() != req.Authority.InstanceID {
		return "", errors.New("Invalid forget instance UUID")
	}
	return "tc-" + strings.ReplaceAll(id.String(), "-", "")[:12], nil
}

func rootForgetLocalParent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("Unclean local metadata path")
	}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("Untrusted local metadata parent %q", p)
		}
		if p == "/" {
			return nil
		}
	}
}

// Remove only an exact symlink and an empty directory, never traverse or recurse.
// The caller holds the instance, authority and volume mount locks.
func rootForgetLocalPaths(link, mount, source string) error {
	for _, p := range []string{link, mount} {
		if p == source || strings.HasPrefix(p, source+"/") {
			return errors.New("Local forget path overlaps shared storage")
		}
		if err := rootForgetLocalParent(p); err != nil {
			return err
		}
	}
	linkExists := false
	if info, err := os.Lstat(link); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return errors.New("Instance path is not the expected local symlink")
		}
		target, err := os.Readlink(link)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(link), target)
		}
		if filepath.Clean(target) != mount {
			return errors.New("Instance link belongs to another local root")
		}
		linkExists = true
	} else if !os.IsNotExist(err) {
		return err
	}
	mountExists := false
	if info, err := os.Lstat(mount); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("Root mount path is not a trusted local directory")
		}
		entries, err := os.ReadDir(mount)
		if err != nil {
			return err
		}
		if len(entries) > 0 {
			return errors.New("Refusing to remove nonempty local root mount path")
		}
		mountExists = true
	} else if !os.IsNotExist(err) {
		return err
	}
	if linkExists {
		if err := os.Remove(link); err != nil {
			return err
		}
	}
	if mountExists {
		if err := os.Remove(mount); err != nil {
			return err
		}
	}
	return nil
}

// ForgetRootMetadata is independent of physical DeleteVolume/DeleteInstance. It
// keeps canonical data/quota/ready records intact and atomically removes DB rows.
// Missing rows are a retry only after the same shared authority and detached-root
// checks, never an unconditional successful DELETE.
func ForgetRootMetadata(pool Pool, req api.XlabRootForgetRequest) (*api.XlabRootForget, error) {
	b, ok := pool.(*backend)
	if !ok || b.driver.Info().Name != "lustre" {
		return nil, errors.New("Forget requires Lustre")
	}
	name, err := rootForgetName(req)
	if err != nil {
		return nil, err
	}
	vol := b.GetVolume(drivers.VolumeTypeContainer, drivers.ContentTypeFS, name, map[string]string{"lustre.volume_id": req.Authority.VolumeID, "lustre.owner_epoch": strconv.FormatUint(req.FormerEpoch, 10), "lustre.generation": strconv.FormatUint(req.Authority.Generation, 10)})
	driver, ok := b.driver.(interface {
		LockRootForget(drivers.Volume, api.XlabRootForgetRequest) (func(), error)
	})
	if !ok {
		return nil, errors.New("Lustre driver lacks metadata-only forget")
	}
	unlock, err := driver.LockRootForget(vol, req)
	if err != nil {
		return nil, err
	}
	defer unlock()
	inst, err := instance.LoadByProjectAndName(b.state, api.ProjectDefaultName, name)
	if err != nil && !response.IsNotFoundError(err) {
		return nil, err
	}
	if err != nil {
		inst = nil
	}
	if err == nil {
		actualPool, e := inst.StoragePool()
		if e != nil {
			return nil, e
		}
		if actualPool != b.Name() {
			return nil, errors.New("Local instance belongs to another storage pool")
		}
		if inst.IsSnapshot() || inst.IsEphemeral() || inst.IsStateful() || len(inst.Profiles()) != 0 || inst.LocalConfig()["user.tc.id"] != req.Authority.InstanceID || inst.LocalConfig()["user.tc.managed"] != "true" {
			return nil, errors.New("Local instance is not the former managed root")
		}
		checker, ok := inst.(interface{ XlabRootForgetQuiesced() error })
		if !ok {
			return nil, errors.New("Instance cannot verify stopped forget")
		}
		if err := checker.XlabRootForgetQuiesced(); err != nil {
			return nil, err
		}
		snapshots, err := inst.Snapshots()
		if err != nil {
			return nil, err
		}
		if len(snapshots) > 0 {
			return nil, errors.New("Forget cannot discard snapshot metadata")
		}
		backups, err := inst.Backups()
		if err != nil {
			return nil, err
		}
		if len(backups) > 0 {
			return nil, errors.New("Forget cannot discard backup metadata")
		}
	}
	local, volErr := VolumeDBGet(pool, api.ProjectDefaultName, name, drivers.VolumeTypeContainer)
	if volErr != nil && !response.IsNotFoundError(volErr) {
		return nil, volErr
	}
	if volErr == nil {
		if local.Config["lustre.volume_id"] != req.Authority.VolumeID || local.Config["lustre.owner_epoch"] != strconv.FormatUint(req.FormerEpoch, 10) || local.Config["lustre.generation"] != strconv.FormatUint(req.Authority.Generation, 10) {
			return nil, errors.New("Local volume belongs to another owner epoch or generation")
		}
	} else {
		local = nil
		if inst != nil {
			return nil, errors.New("Existing instance lacks its former root volume identity")
		}
	}
	snapshots, err := VolumeDBSnapshotsGet(pool, api.ProjectDefaultName, name, drivers.VolumeTypeContainer)
	if err != nil && !response.IsNotFoundError(err) {
		return nil, err
	}
	if len(snapshots) > 0 {
		return nil, errors.New("Forget cannot discard root snapshot metadata")
	}
	if err := rootForgetLocalPaths(InstancePath(instancetype.Container, api.ProjectDefaultName, name, false), vol.MountPath(), req.Source); err != nil {
		return nil, err
	}
	volType, err := VolumeTypeToDBType(drivers.VolumeTypeContainer)
	if err != nil {
		return nil, err
	}
	err = b.state.DB.Cluster.Transaction(context.TODO(), func(ctx context.Context, tx *db.ClusterTx) error {
		if local != nil {
			if err := tx.RemoveStoragePoolVolume(ctx, api.ProjectDefaultName, name, volType, b.ID()); err != nil {
				return err
			}
		}
		if inst != nil {
			return tx.DeleteInstance(ctx, api.ProjectDefaultName, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := b.state.Authorizer.DeleteStoragePoolVolume(b.state.ShutdownCtx, api.ProjectDefaultName, b.Name(), drivers.VolumeTypeContainer.Singular(), name, ""); err != nil {
		return nil, err
	}
	if err := b.state.Authorizer.DeleteInstance(b.state.ShutdownCtx, api.ProjectDefaultName, name); err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	return &api.XlabRootForget{XlabRootForgetRequest: req, BootID: strings.TrimSpace(string(boot)), LocalMetadataGone: true, RootRetained: true}, nil
}
