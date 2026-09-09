package drivers

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/lxc/incus/v6/internal/linux"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/idmap"
	"golang.org/x/sys/unix"
)

// LockRootStart is held until the complete Incus startup (or file-connection
// setup) returns. Publishing releasing waits for all earlier startups to finish.
func (d *lustre) LockRootStart(vol Volume) (func(), error) {
	unlock, err := d.lockAuthority(vol)
	if err != nil {
		return nil, err
	}
	a, path, err := d.authority(vol)
	if err == nil {
		err = a.checkStart()
	}
	if err == nil {
		err = lustreCheckReady(a, path)
	}
	if err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

func (a lustreAuthority) checkStart() error {
	if a.Phase != "attached" {
		return errors.New("Root startup requires published attached authority")
	}
	return nil
}

func (a lustreAuthority) checkRelease(req api.XlabRootReleaseRequest) error {
	if a.Phase != "releasing" || req.VolumeID != a.VolumeID || req.InstanceID != a.InstanceID || req.OwnerID != a.OwnerID || req.Epoch != a.Epoch || req.Generation != a.Generation || req.Revision != a.Revision {
		return errors.New("Root release does not match the current releasing authority")
	}
	return nil
}

// ReleaseRoot never grants a new owner. Its result is evidence for the controller
// to acknowledge separately, after this call has actually synced and detached.
func (d *lustre) ReleaseRoot(vol Volume, req api.XlabRootReleaseRequest, quiesce func() error, capture func(*idmap.Set) (*api.XlabRootMetadata, error)) (*api.XlabRootRelease, error) {
	unlockAuthority, err := d.lockAuthority(vol)
	if err != nil {
		return nil, err
	}
	defer unlockAuthority()
	a, source, err := d.readAuthority(vol)
	if err != nil {
		return nil, err
	}
	if err := a.checkRelease(req); err != nil {
		return nil, err
	}
	if quiesce == nil || capture == nil {
		return nil, errors.New("Root release requires instance quiescence")
	}
	if err := quiesce(); err != nil {
		return nil, err
	}
	unlockMount, err := vol.MountLock()
	if err != nil {
		return nil, err
	}
	defer unlockMount()
	if vol.MountInUse() {
		return nil, ErrInUse
	}
	if err := lustreTrustedDirectory(source); err != nil {
		return nil, err
	}
	if err := lustreCheckReady(a, source); err != nil {
		return nil, err
	}
	if err := lustreNoNestedMounts(source); err != nil {
		return nil, err
	}
	root, err := os.OpenFile(source, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	// Flush this client's filesystem writes before confirming ordinary unmount.
	if err := unix.Syncfs(int(root.Fd())); err != nil {
		return nil, err
	}
	if linux.IsMountPoint(vol.MountPath()) {
		if !sameMount(source, vol.MountPath()) {
			return nil, errors.New("Local root mount belongs to another generation")
		}
		if err := unix.Unmount(vol.MountPath(), 0); err != nil {
			return nil, err
		}
	}
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	if err := lustreCheckDetached(d.config["source"], source, string(raw)); err != nil {
		return nil, err
	}
	wantMap, err := lustreDiskIDMap(a.IDMap)
	if err != nil {
		return nil, err
	}
	metadata, err := capture(wantMap)
	if err != nil {
		return nil, err
	}
	if metadata == nil {
		return nil, errors.New("Missing stopped metadata")
	}
	if err := metadata.Validate(); err != nil {
		return nil, err
	}
	fid, err := lustreRootFID(filepath.Join(source, "rootfs"))
	if err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	bootID := strings.TrimSpace(string(boot))
	if err := lustreCanonicalUUID(bootID); err != nil {
		return nil, err
	}
	return &api.XlabRootRelease{XlabRootReleaseRequest: req, RootFID: fid, Metadata: metadata, BootID: bootID, InstanceStopped: true, RestartBlocked: true, RootDetached: true}, nil
}

// Check both the normal Incus bind and aliases of any subtree of this generation
// in the daemon mount namespace. The common Lustre source mount itself is retained.
func lustreCheckDetached(poolSource, generation, raw string) error {
	type mount struct{ device, root, target string }
	mounts := []mount{}
	decode := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	var parent *mount
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			return errors.New("Malformed mountinfo during release")
		}
		m := mount{device: f[2], root: decode.Replace(f[3]), target: decode.Replace(f[4])}
		mounts = append(mounts, m)
		if m.target == poolSource {
			if parent != nil {
				return errors.New("Stacked pool source during release")
			}
			copy := m
			parent = &copy
		}
	}
	if parent == nil {
		return errors.New("Lustre source disappeared during release")
	}
	rel, err := filepath.Rel(poolSource, generation)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return errors.New("Generation is outside source")
	}
	generationRoot := filepath.Join(parent.root, rel)
	for _, m := range mounts {
		if m.device == parent.device && (m.root == generationRoot || strings.HasPrefix(m.root, generationRoot+"/")) {
			return errors.New("Root generation or a subtree remains mounted")
		}
	}
	return nil
}
