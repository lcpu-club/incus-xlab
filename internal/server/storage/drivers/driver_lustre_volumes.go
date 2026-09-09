package drivers

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/lxc/incus/v6/internal/linux"
	"github.com/lxc/incus/v6/internal/server/operations"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/subprocess"
)

type lustreReady struct {
	IDMap      api.XlabRootIDMap `json:"id_map"`
	VolumeID   string            `json:"volume_id"`
	Generation uint64            `json:"generation"`
	ProjectID  uint32            `json:"project_id"`
}

func lustreReadyPath(path string) string {
	return path + ".ready.json"
}

func lustreCheckReady(authority *lustreAuthority, path string) error {
	var ready lustreReady
	err := lustreReadJSON(lustreReadyPath(path), &ready)
	if err != nil {
		return err
	}
	if ready.IDMap != authority.IDMap || ready.IDMap.Validate() != nil || ready.VolumeID != authority.VolumeID || ready.Generation != authority.Generation || ready.ProjectID != authority.ProjectID {
		return errors.New("Root generation completion record does not match allocation")
	}
	return nil
}

func lustreWriteReady(authority *lustreAuthority, path string) error {
	data, err := json.Marshal(lustreReady{IDMap: authority.IDMap, VolumeID: authority.VolumeID, Generation: authority.Generation, ProjectID: authority.ProjectID})
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".ready-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	_, err = file.Write(data)
	if err != nil {
		return err
	}
	err = file.Sync()
	if err != nil {
		return err
	}
	err = file.Close()
	if err != nil {
		return err
	}
	err = os.Rename(file.Name(), lustreReadyPath(path))
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (d *lustre) mountRoot(vol Volume, requireReady bool, op *operations.Operation) error {
	unlock, err := vol.MountLock()
	if err != nil {
		return err
	}
	defer unlock()
	authority, source, err := d.authority(vol)
	if err != nil {
		return err
	}
	if authority.Phase == "destroy" {
		return errors.New("Cannot mount a root authorized for destruction")
	}
	if requireReady {
		err = lustreCheckReady(authority, source)
		if err != nil {
			return err
		}
	}
	_, err = d.quota(vol, false)
	if err != nil {
		return err
	}
	path := vol.MountPath()
	if linux.IsMountPoint(path) {
		if !sameMount(source, path) {
			return errors.New("Root mount refers to another generation or filesystem")
		}
	} else {
		err = vol.EnsureMountPath(false)
		if err != nil {
			return err
		}
		err = lustreTrustedDirectory(path)
		if err != nil {
			return err
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return errors.New("Refusing to cover a nonempty local root directory")
		}
		err = TryMount(source, path, "none", unix.MS_BIND, "")
		if err != nil {
			return err
		}
	}
	vol.MountRefCountIncrement()
	return nil
}

func (d *lustre) MountVolume(vol Volume, op *operations.Operation) error {
	unlockAuthority, err := d.lockAuthority(vol)
	if err != nil {
		return err
	}
	defer unlockAuthority()
	return d.mountRoot(vol, true, op)
}

// UnmountVolume can release an old local bind after authority has moved elsewhere.
func (d *lustre) UnmountVolume(vol Volume, keepBlockDev bool, op *operations.Operation) (bool, error) {
	id, _, generation, err := lustreVolumeIdentity(vol)
	if err != nil {
		return false, err
	}
	unlock, err := vol.MountLock()
	if err != nil {
		return false, err
	}
	defer unlock()
	if vol.MountRefCountDecrement() > 0 {
		return false, ErrInUse
	}
	if !linux.IsMountPoint(vol.MountPath()) {
		return false, nil
	}
	source := filepath.Join(d.config["source"], "roots", id, "generations", strconv.FormatUint(generation, 10))
	if !sameMount(source, vol.MountPath()) {
		return false, errors.New("Refusing to unmount another root or filesystem")
	}
	err = unix.Unmount(vol.MountPath(), 0)
	if err != nil {
		return false, err
	}
	return true, nil
}

// CreateVolume assigns inherited project quota before any image extraction.
func (d *lustre) CreateVolume(vol Volume, filler *VolumeFiller, op *operations.Operation) (err error) {
	unlockAuthority, err := d.lockAuthority(vol)
	if err != nil {
		return err
	}
	defer unlockAuthority()
	authority, path, err := d.authority(vol)
	if err != nil {
		return err
	}
	if authority.Phase != "creating" {
		return errors.New("Root creation requires creating authority")
	}
	base := filepath.Join(d.config["source"], "roots")
	err = lustreTrustedDirectory(base)
	if err != nil {
		return err
	}
	for _, dir := range []string{filepath.Join(base, authority.VolumeID), filepath.Dir(path)} {
		err = os.Mkdir(dir, 0o700)
		if err != nil && !os.IsExist(err) {
			return err
		}
		err = lustreTrustedDirectory(dir)
		if err != nil {
			return err
		}
	}
	err = os.Mkdir(path, 0o711)
	if os.IsExist(err) {
		err = lustreTrustedDirectory(path)
		if err != nil {
			return err
		}
		err = lustreCheckReady(authority, path)
		if err != nil {
			return fmt.Errorf("Incomplete root generation requires explicit cleanup: %w", err)
		}
		_, err = d.quota(vol, false)
		return err
	}
	if err != nil {
		return err
	}
	// Failed creations remain isolated; explicit destroy authority permits retry cleanup.
	project := strconv.FormatUint(uint64(authority.ProjectID), 10)
	_, err = subprocess.RunCommandCLocale("lfs", "project", "-p", project, "-s", path)
	if err != nil {
		return err
	}
	_, err = d.quota(vol, true)
	if err != nil {
		return err
	}
	err = d.mountRoot(vol, false, op)
	if err != nil {
		return err
	}
	defer func() {
		_, unmountErr := d.UnmountVolume(vol, false, op)
		if err == nil {
			err = unmountErr
		}
	}()
	err = genericRunFiller(d, vol, "", filler, false)
	if err != nil {
		return err
	}
	rootfs, err := os.Lstat(filepath.Join(path, "rootfs"))
	if err != nil || !rootfs.IsDir() {
		return errors.New("Root creation did not produce a rootfs directory")
	}
	rootStat, ok := rootfs.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != authority.IDMap.Base || rootStat.Gid != authority.IDMap.Base {
		return errors.New("Root creation did not preserve its allocated disk identity")
	}
	current, _, err := d.authority(vol)
	if err != nil {
		return err
	}
	if *current != *authority {
		return errors.New("Root authority changed during image extraction")
	}
	_, err = d.quota(vol, false)
	if err != nil {
		return err
	}
	root, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := unix.Syncfs(int(root.Fd())); err != nil {
		return err
	}
	return lustreWriteReady(authority, path)
}

// DeleteVolume removes only the explicitly authorized generation, never external mounts.
func (d *lustre) DeleteVolume(vol Volume, op *operations.Operation) error {
	unlockAuthority, err := d.lockAuthority(vol)
	if err != nil {
		return err
	}
	defer unlockAuthority()
	authority, path, err := d.authority(vol)
	if err != nil {
		return err
	}
	if authority.Phase != "destroy" {
		return errors.New("Root deletion requires explicit destroy authority")
	}
	unlock, err := vol.MountLock()
	if err != nil {
		return err
	}
	defer unlock()
	if vol.MountInUse() || linux.IsMountPoint(vol.MountPath()) {
		return ErrInUse
	}
	err = lustreTrustedDirectory(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	// Refuse any nested mount before traversing the canonical generation.
	_, err = d.quota(vol, false)
	if err != nil {
		return err
	}
	err = lustreNoNestedMounts(path)
	if err != nil {
		return err
	}
	err = os.RemoveAll(path)
	if err != nil {
		return err
	}
	err = os.Remove(lustreReadyPath(path))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// Keep the project limit and volume parent until platform reclamation completes.
	return nil
}

func lustreNoNestedMounts(path string) error {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer file.Close()
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			return errors.New("Malformed mountinfo")
		}
		mount := unescape.Replace(fields[4])
		if mount == path || strings.HasPrefix(mount, path+"/") {
			return errors.New("Root generation contains a mount")
		}
	}
	return scanner.Err()
}
