package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/lxc/incus/v6/shared/archive"
	"github.com/lxc/incus/v6/shared/idmap"
	"github.com/lxc/incus/v6/shared/ioprogress"
)

// imageUnpackMapped populates an already project-quota-assigned generation.
// Only staging is mapped-owned; the canonical directory stays host-root-owned.
// Failed/partial staging is retained and cannot be mistaken for a ready root.
// The caller must own creation of the new canonical generation (the Lustre driver
// wins its atomic mkdir) and hold authority through publication. Until ready,
// no guest can mount it; root-owned ancestors exclude mapped image identities.
func imageUnpackMapped(image, destination string, maxMemory int64, tracker *ioprogress.ProgressTracker, diskMap *idmap.Set) error {
	namespace := archive.UnpackNamespace{UID: diskMap.ToUIDMappings(), GID: diskMap.ToGIDMappings()}
	if err := namespace.Validate(); err != nil {
		return err
	}
	rootUID, rootGID := -1, -1
	for _, m := range namespace.UID {
		if m.ContainerID == 0 {
			rootUID = m.HostID
		}
	}
	for _, m := range namespace.GID {
		if m.ContainerID == 0 {
			rootGID = m.HostID
		}
	}
	parent, err := os.OpenFile(destination, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	info, err := parent.Stat()
	if err != nil {
		return err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("Mapped image publication requires root-owned private scaffolding")
	}
	stage, err := os.MkdirTemp(destination, ".unpack-")
	if err != nil {
		return err
	}
	if err := os.Chown(stage, rootUID, rootGID); err != nil {
		return err
	}
	if err := archive.UnpackMapped(image, stage, maxMemory, tracker, namespace); err != nil {
		return err
	}
	rootfs := filepath.Join(stage, "rootfs")
	if _, err := os.Stat(image + ".rootfs"); err == nil {
		if err := os.Mkdir(rootfs, 0755); err != nil && !os.IsExist(err) {
			return err
		}
		info, err := os.Lstat(rootfs)
		if err != nil || !info.IsDir() {
			return errors.New("Split image rootfs must be a real directory")
		}
		if err := os.Chown(rootfs, rootUID, rootGID); err != nil {
			return err
		}
		if err := archive.UnpackMapped(image+".rootfs", rootfs, maxMemory, tracker, namespace); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	info, err = os.Lstat(rootfs)
	if err != nil || !info.IsDir() {
		return errors.New("Mapped image is missing a real rootfs directory")
	}
	stat = info.Sys().(*syscall.Stat_t)
	if int(stat.Uid) != rootUID || int(stat.Gid) != rootGID {
		return errors.New("Mapped image rootfs has the wrong root identity")
	}
	entries, err := os.ReadDir(stage)
	if err != nil {
		return err
	}
	stageDir, err := os.OpenFile(stage, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer stageDir.Close()
	// Lustre 2.17 ll_rename rejects all nonzero rename flags. Under the driver's
	// exclusive new-generation creation claim, check every destination before
	// using ordinary rename. Do not use this helper to merge an existing root.
	for _, entry := range entries {
		var existing unix.Stat_t
		err := unix.Fstatat(int(parent.Fd()), entry.Name(), &existing, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return fmt.Errorf("Mapped image destination %q already exists", entry.Name())
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	for _, entry := range entries {
		if err := unix.Renameat(int(stageDir.Fd()), entry.Name(), int(parent.Fd()), entry.Name()); err != nil {
			return fmt.Errorf("Publish mapped image %q: %w", entry.Name(), err)
		}
	}
	if err := os.Remove(stage); err != nil {
		return err
	}
	return nil // The driver syncs the populated generation before publishing ready.
}
