package drivers

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lxc/incus/v6/internal/linux"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/idmap"
	"github.com/lxc/incus/v6/shared/osarch"
)

func (a lustreAuthority) checkPrepare(req api.XlabRootPrepareRequest, target string, localArch string) error {
	if a != lustreAuthority(req.Authority) || a.Phase != "attached" || a.OwnerID == target || req.TargetOwnerID != target || lustreCanonicalUUID(target) != nil || lustreCanonicalUUID(req.OperationID) != nil || (req.Architecture != "aarch64" && req.Architecture != "x86_64") || req.Architecture != localArch {
		return errors.New("Prepare requires exact source authority, a different target and matching native architecture")
	}
	return nil
}

// PrepareRoot verifies the source root without adopting it or allowing local IO.
// It is a point-in-time preflight, not fencing or a reservation lease. Adoption
// must verify authority, delegation and local absence again after source release.
func (d *lustre) PrepareRoot(vol Volume, req api.XlabRootPrepareRequest, checkLocal func() error) (*api.XlabRootPreparation, error) {
	id, epoch, generation, err := lustreVolumeIdentity(vol)
	if err != nil {
		return nil, err
	}
	if req.Pool != vol.Pool() || req.Source != d.config["source"] {
		return nil, errors.New("Preparation differs from target pool binding")
	}
	unlock, err := d.lockAuthority(vol)
	if err != nil {
		return nil, err
	}
	defer unlock()
	var current lustreAuthority
	if err := lustreReadJSON(filepath.Join(req.Source, "control", "roots", id+".json"), &current); err != nil {
		return nil, err
	}
	if err := current.validateIdentity(id, current.OwnerID, epoch, generation, vol.name); err != nil {
		return nil, err
	}
	arch, err := osarch.ArchitectureGetLocal()
	if err != nil {
		return nil, err
	}
	if err := current.checkPrepare(req, d.config["lustre.host_id"], arch); err != nil {
		return nil, err
	}
	root := filepath.Join(req.Source, "roots", id, "generations", strconv.FormatUint(generation, 10))
	if err := lustreCheckReady(&current, root); err != nil {
		return nil, err
	}
	if _, err := lustreQuota(&current, root, req.Source, false); err != nil {
		return nil, err
	}
	want, err := lustreDiskIDMap(current.IDMap)
	if err != nil {
		return nil, err
	}
	delegated, err := idmap.NewSetFromSystem("root")
	if err != nil {
		return nil, err
	}
	if delegated == nil || !delegated.Includes(want) {
		return nil, errors.New("Target does not delegate the persistent root ID map")
	}
	fid, err := lustreRootFID(filepath.Join(root, "rootfs"))
	if err != nil {
		return nil, err
	}
	if fid != req.RootFID {
		return nil, errors.New("Target sees a different root FID")
	}
	mountUnlock, err := vol.MountLock()
	if err != nil {
		return nil, err
	}
	defer mountUnlock()
	if vol.MountInUse() || linux.IsMountPoint(vol.MountPath()) {
		return nil, ErrInUse
	}
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	if err := lustreCheckDetached(req.Source, root, string(raw)); err != nil {
		return nil, err
	}
	if checkLocal == nil {
		return nil, errors.New("Preparation requires local metadata absence check")
	}
	if err := checkLocal(); err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	return &api.XlabRootPreparation{XlabRootPrepareRequest: req, BootID: strings.TrimSpace(string(boot)), LocalMetadataAbsent: true, IDMapDelegated: true, Ready: true}, nil
}
