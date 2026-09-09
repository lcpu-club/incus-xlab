package storage

import (
	"archive/tar"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/lxc/incus/v6/shared/idmap"
)

func mappedImageFixture(t *testing.T, base string, split bool) string {
	t.Helper()
	image := filepath.Join(base, "image.tar")
	write := func(name string, headers []tar.Header) {
		f, err := os.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w := tar.NewWriter(f)
		for _, header := range headers {
			if err := w.WriteHeader(&header); err != nil {
				t.Fatal(err)
			}
			if header.Size > 0 {
				if _, err := w.Write([]byte("payload")); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	meta := []tar.Header{{Name: "metadata.yaml", Typeflag: tar.TypeReg, Mode: 0644, Size: 7}}
	root := []tar.Header{
		{Name: "rootfs/", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "rootfs/sentinel", Typeflag: tar.TypeReg, Mode: 0640, Uid: 10000, Gid: 10000, Size: 7},
		{Name: "rootfs/link", Typeflag: tar.TypeLink, Linkname: "rootfs/sentinel", Mode: 0640, Uid: 10000, Gid: 10000},
	}
	if split {
		write(image, meta)
		write(image+".rootfs", []tar.Header{
			{Name: "sentinel", Typeflag: tar.TypeReg, Mode: 0640, Uid: 10000, Gid: 10000, Size: 7},
			{Name: "link", Typeflag: tar.TypeLink, Linkname: "sentinel", Mode: 0640, Uid: 10000, Gid: 10000},
		})
	} else {
		write(image, append(meta, root...))
	}
	return image
}

func mappedImageDiskMap() *idmap.Set {
	return &idmap.Set{Entries: []idmap.Entry{
		{IsUID: true, IsGID: true, HostID: 1000000, NSID: 0, MapRange: 10000},
		{IsUID: true, IsGID: true, HostID: 10000, NSID: 10000, MapRange: 1},
		{IsUID: true, IsGID: true, HostID: 1010001, NSID: 10001, MapRange: 55535},
	}}
}

func TestMappedImagePublication(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Run compiled storage tests as root for real mapped image creation")
	}
	for _, format := range []string{"combined-tar", "split-tar", "split-squashfs"} {
		t.Run(format, func(t *testing.T) {
			base := t.TempDir()
			image := mappedImageFixture(t, base, format != "combined-tar")
			if format == "split-squashfs" {
				source := filepath.Join(base, "source")
				if err := os.Mkdir(source, 0755); err != nil {
					t.Fatal(err)
				}
				file := filepath.Join(source, "sentinel")
				if err := os.WriteFile(file, []byte("payload"), 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(file, 10000, 10000); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(file, filepath.Join(source, "link")); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(image + ".rootfs"); err != nil {
					t.Fatal(err)
				}
				out, err := exec.Command("mksquashfs", source, image+".rootfs", "-noappend", "-processors", "1", "-quiet").CombinedOutput()
				if err != nil {
					t.Fatalf("Build fixture: %v %s", err, out)
				}
			}
			dest := filepath.Join(base, "generation")
			if err := os.Mkdir(dest, 0700); err != nil {
				t.Fatal(err)
			}
			if err := imageUnpackMapped(image, dest, 64<<20, nil, mappedImageDiskMap()); err != nil {
				t.Fatal(err)
			}
			for _, item := range []struct {
				path string
				uid  uint32
			}{{".", 0}, {"rootfs", 1000000}, {"metadata.yaml", 1000000}, {"rootfs/sentinel", 10000}} {
				info, err := os.Stat(filepath.Join(dest, item.path))
				if err != nil {
					t.Fatal(err)
				}
				stat := info.Sys().(*syscall.Stat_t)
				if stat.Uid != item.uid || stat.Gid != item.uid {
					t.Fatalf("Wrong ownership on %s: %d:%d", item.path, stat.Uid, stat.Gid)
				}
			}
			payload, err := os.ReadFile(filepath.Join(dest, "rootfs/sentinel"))
			if err != nil || string(payload) != "payload" {
				t.Fatalf("Bad root payload %q %v", payload, err)
			}
			one, err := os.Stat(filepath.Join(dest, "rootfs/sentinel"))
			if err != nil {
				t.Fatal(err)
			}
			two, err := os.Stat(filepath.Join(dest, "rootfs/link"))
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(one, two) {
				t.Fatal("Publication broke hardlink identity")
			}
			stages, err := filepath.Glob(filepath.Join(dest, ".unpack-*"))
			if err != nil || len(stages) != 0 {
				t.Fatal("Completed image retained staging")
			}
			// A repeated partial/ambiguous create never overwrites published files.
			if err := imageUnpackMapped(image, dest, 64<<20, nil, mappedImageDiskMap()); err == nil {
				t.Fatal("Repeated extraction overwrote existing generation")
			}
			after, err := os.Stat(filepath.Join(dest, "rootfs/sentinel"))
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(one, after) {
				t.Fatal("Failed publication replaced existing root")
			}
		})
	}
}
