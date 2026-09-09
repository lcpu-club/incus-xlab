package drivers

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"github.com/lxc/incus/v6/internal/linux"
	"github.com/lxc/incus/v6/shared/api"
)

func (a lustreAuthority) checkForget(req api.XlabRootForgetRequest, localOwner string, oldEpoch uint64) error {
	if a != lustreAuthority(req.Authority) || a.Phase != "attached" || req.FormerOwnerID != localOwner || req.FormerEpoch == 0 || req.FormerEpoch != oldEpoch || a.Epoch <= 1 || a.Epoch-1 != oldEpoch || a.OwnerID == localOwner || lustreCanonicalUUID(a.OwnerID) != nil {
		return errors.New("Forget requires the next owner's current attached grant and exact former epoch")
	}
	return nil
}

// LockRootForget deliberately reads the next owner's authority. Normal root IO
// still uses readAuthority, which requires local ownership. This permits only
// metadata cleanup while holding both authority and local mount locks.
func (d *lustre) LockRootForget(vol Volume, req api.XlabRootForgetRequest) (func(), error) {
	id, epoch, generation, err := lustreVolumeIdentity(vol)
	if err != nil {
		return nil, err
	}
	if req.Pool != vol.Pool() || req.Source != d.config["source"] || req.Authority.VolumeID != id || req.Authority.Generation != generation {
		return nil, errors.New("Forget does not match local root binding")
	}
	unlock, err := d.lockAuthority(vol)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (func(), error) { unlock(); return nil, err }
	var current lustreAuthority
	if err := lustreReadJSON(filepath.Join(req.Source, "control", "roots", id+".json"), &current); err != nil {
		return fail(err)
	}
	if err := current.validateIdentity(id, current.OwnerID, current.Epoch, generation, vol.name); err != nil {
		return fail(err)
	}
	if err := current.checkForget(req, d.config["lustre.host_id"], epoch); err != nil {
		return fail(err)
	}
	root := filepath.Join(req.Source, "roots", id, "generations", strconv.FormatUint(generation, 10))
	if err := lustreCheckReady(&current, root); err != nil {
		return fail(err)
	}
	fid, err := lustreRootFID(filepath.Join(root, "rootfs"))
	if err != nil {
		return fail(err)
	}
	if fid != req.RootFID {
		return fail(errors.New("Forget requires retained canonical root FID"))
	}
	mountUnlock, err := vol.MountLock()
	if err != nil {
		return fail(err)
	}
	both := func() { mountUnlock(); unlock() }
	if vol.MountInUse() || linux.IsMountPoint(vol.MountPath()) {
		both()
		return nil, ErrInUse
	}
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err == nil {
		err = lustreCheckDetached(req.Source, root, string(raw))
	}
	if err != nil {
		both()
		return nil, err
	}
	return both, nil
}
