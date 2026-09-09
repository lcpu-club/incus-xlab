package apparmor

import (
	"archive/tar"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/lxc/incus/v6/internal/server/sys"
	"github.com/lxc/incus/v6/shared/archive"
)

// This opt-in test loads only temporary archive profiles on the local test host.
// It deliberately fails (rather than disabling confinement) when enabled and
// user namespaces, AppArmor administration or the extractor tools are unavailable.
func TestMappedArchiveAppArmor(t *testing.T) {
	if os.Getenv("XLAB_ARCHIVE_APPARMOR_TEST") != "1" {
		t.Skip("Set XLAB_ARCHIVE_APPARMOR_TEST=1 and run as root to test real confinement")
	}
	if os.Geteuid() != 0 {
		t.Fatal("Requires root")
	}
	previousPath, previousCache, previousVersion := aaPath, aaCacheDir, aaVersion
	previousWrapper := archive.RunWrapper
	t.Cleanup(func() {
		aaPath, aaCacheDir, aaVersion = previousPath, previousCache, previousVersion
		archive.RunWrapper = previousWrapper
	})
	base := t.TempDir()
	t.Setenv("INCUS_DIR", base)
	imageCache := filepath.Join(base, "images")
	if err := os.Mkdir(imageCache, 0700); err != nil {
		t.Fatal(err)
	}
	aaPath = filepath.Join(base, "apparmor")
	for _, dir := range []string{"profiles", "cache"} {
		if err := os.MkdirAll(filepath.Join(aaPath, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	sysOS := &sys.OS{AppArmorAvailable: true, AppArmorAdmin: true}
	var profiles []string
	archive.RunWrapper = func(cmd *exec.Cmd, output string, allowed []string) (func(), error) {
		cleanup, err := ArchiveWrapper(sysOS, cmd, output, allowed)
		if err != nil {
			return nil, err
		}
		name := cmd.Args[2]
		profiles = append(profiles, name)
		loaded, err := hasProfile(sysOS, name)
		if err != nil || !loaded {
			t.Errorf("Profile not loaded: %s %v", name, err)
		}
		return cleanup, nil
	}
	namespace := archive.UnpackNamespace{
		UID: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000000, Size: 65536}},
		GID: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000000, Size: 65536}},
	}
	for _, format := range []string{"tar", "squashfs"} {
		t.Run(format, func(t *testing.T) {
			private := t.TempDir()
			name := filepath.Join(imageCache, format+".tar")
			f, err := os.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			w := tar.NewWriter(f)
			if err := w.WriteHeader(&tar.Header{Name: "sentinel", Mode: 0640, Size: 7}); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte("payload")); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if format == "squashfs" {
				source := filepath.Join(private, "source")
				if err := os.Mkdir(source, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(source, "sentinel"), []byte("payload"), 0640); err != nil {
					t.Fatal(err)
				}
				name = filepath.Join(imageCache, "image.squashfs")
				out, err := exec.Command("mksquashfs", source, name, "-noappend", "-processors", "1", "-quiet").CombinedOutput()
				if err != nil {
					t.Fatalf("Build squashfs: %v: %s", err, out)
				}
			}
			dest := filepath.Join(private, "output")
			if err := os.Mkdir(dest, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(dest, 1000000, 1000000); err != nil {
				t.Fatal(err)
			}
			if err := archive.UnpackMapped(name, dest, 64*1024*1024, nil, namespace); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(dest, "sentinel"))
			if err != nil || string(data) != "payload" {
				t.Fatalf("Bad payload %q: %v", data, err)
			}
			stat, err := os.Stat(filepath.Join(dest, "sentinel"))
			if err != nil {
				t.Fatal(err)
			}
			owner := stat.Sys().(*syscall.Stat_t)
			if owner.Uid != 1000000 || owner.Gid != 1000000 {
				t.Fatalf("Wrong ownership: %d:%d", owner.Uid, owner.Gid)
			}
		})
	}
	if len(profiles) != 2 {
		t.Errorf("Expected two confined extractors, saw %d", len(profiles))
	}
	for _, name := range profiles {
		loaded, err := hasProfile(sysOS, name)
		if err != nil || loaded {
			t.Errorf("Temporary profile not removed: %s %v", name, err)
		}
	}
}
