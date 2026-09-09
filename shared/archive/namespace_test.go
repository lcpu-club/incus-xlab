//go:build linux

package archive

import (
	"archive/tar"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func testUnpackNamespace() UnpackNamespace {
	ids := []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: 1000000, Size: 10000},
		{ContainerID: 10000, HostID: 10000, Size: 1},
		{ContainerID: 10001, HostID: 1010001, Size: 55535},
	}
	return UnpackNamespace{UID: ids, GID: slices.Clone(ids)}
}

func TestUnpackNamespaceValidation(t *testing.T) {
	valid := testUnpackNamespace()
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*UnpackNamespace)
	}{
		{"missing UID", func(n *UnpackNamespace) { n.UID = nil }},
		{"missing GID", func(n *UnpackNamespace) { n.GID = nil }},
		{"host root", func(n *UnpackNamespace) { n.UID[0].HostID = 0 }},
		{"negative host", func(n *UnpackNamespace) { n.GID[0].HostID = -1 }},
		{"overflow host", func(n *UnpackNamespace) { n.UID[0].HostID = 4294967294 }},
		{"invalid host ID", func(n *UnpackNamespace) { n.UID[1].HostID = 4294967295 }},
		{"missing root", func(n *UnpackNamespace) { n.UID[0].ContainerID = 1 }},
		{"container overlap", func(n *UnpackNamespace) { n.GID[1].ContainerID = 9999 }},
		{"host overlap", func(n *UnpackNamespace) { n.UID[1].HostID = 1000001 }},
		{"missing last ID", func(n *UnpackNamespace) { n.GID[2].Size-- }},
		{"extra ID", func(n *UnpackNamespace) { n.GID[2].Size++ }},
		{"negative size", func(n *UnpackNamespace) { n.UID[0].Size = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := testUnpackNamespace()
			tc.change(&n)
			if n.Validate() == nil {
				t.Fatal("Invalid namespace accepted")
			}
		})
	}
	// Ordering is not significant, and validation must not mutate the caller.
	slices.Reverse(valid.UID)
	before := slices.Clone(valid.UID)
	if err := valid.Validate(); err != nil || !slices.Equal(before, valid.UID) {
		t.Fatalf("Unordered mapping: %v, mutated=%v", err, !slices.Equal(before, valid.UID))
	}
}

func testCapability() []byte {
	capability := make([]byte, 20)
	binary.LittleEndian.PutUint32(capability, 0x02000001)
	binary.LittleEndian.PutUint32(capability[4:], 1<<10) // CAP_NET_BIND_SERVICE, effective.
	return capability
}

func makeMappedTestImage(t *testing.T, base string) string {
	t.Helper()
	name := filepath.Join(base, "image.tar")
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	w := tar.NewWriter(f)
	for _, entry := range []struct {
		h    tar.Header
		body string
	}{
		{tar.Header{Name: "rootfs/", Typeflag: tar.TypeDir, Mode: 0755}, ""},
		{tar.Header{Name: "rootfs/hello", Typeflag: tar.TypeReg, Mode: 0640, Uid: 10000, Gid: 10000, Xattrs: map[string]string{"user.xlab": "mapped"}}, "retained payload\n"},
		{tar.Header{Name: "rootfs/hardlink", Typeflag: tar.TypeLink, Linkname: "rootfs/hello", Mode: 0640, Uid: 10000, Gid: 10000}, ""},
		{tar.Header{Name: "rootfs/capability", Typeflag: tar.TypeReg, Mode: 0755, Xattrs: map[string]string{"security.capability": string(testCapability())}}, "capability payload\n"},
	} {
		entry.h.Size = int64(len(entry.body))
		if err := w.WriteHeader(&entry.h); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return name
}

func mappedTestOutput(t *testing.T, base string) string {
	t.Helper()
	dest := filepath.Join(base, "output")
	if err := os.Mkdir(dest, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dest, 1000000, 1000000); err != nil {
		t.Fatal(err)
	}
	return dest
}

func checkMappedTestOutput(t *testing.T, dest string) {
	t.Helper()
	var first, second unix.Stat_t
	for _, item := range []struct {
		path     string
		uid, gid uint32
		mode     uint32
	}{
		{"rootfs", 1000000, 1000000, 0755},
		{"rootfs/hello", 10000, 10000, 0640},
		{"rootfs/capability", 1000000, 1000000, 0755},
	} {
		var stat unix.Stat_t
		if err := unix.Stat(filepath.Join(dest, item.path), &stat); err != nil {
			t.Fatal(err)
		}
		if stat.Uid != item.uid || stat.Gid != item.gid || stat.Mode&07777 != item.mode {
			t.Errorf("%s: uid=%d gid=%d mode=%o", item.path, stat.Uid, stat.Gid, stat.Mode&07777)
		}
	}
	if err := unix.Stat(filepath.Join(dest, "rootfs/hello"), &first); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(filepath.Join(dest, "rootfs/hardlink"), &second); err != nil {
		t.Fatal(err)
	}
	if first.Ino != second.Ino || first.Nlink != 2 {
		t.Fatal("Hardlink was not preserved")
	}
	data, err := os.ReadFile(filepath.Join(dest, "rootfs/hello"))
	if err != nil || string(data) != "retained payload\n" {
		t.Fatalf("Payload: %q %v", data, err)
	}
	buf := make([]byte, 128)
	n, err := unix.Getxattr(filepath.Join(dest, "rootfs/hello"), "user.xlab", buf)
	if err != nil || string(buf[:n]) != "mapped" {
		t.Fatalf("User xattr: %v", err)
	}
	n, err = unix.Getxattr(filepath.Join(dest, "rootfs/capability"), "security.capability", buf)
	if err != nil || n != 24 {
		t.Fatalf("Namespaced capability: size=%d err=%v", n, err)
	}
	if binary.LittleEndian.Uint32(buf) != 0x03000001 || binary.LittleEndian.Uint32(buf[4:]) != 1<<10 || binary.LittleEndian.Uint32(buf[20:]) != 1000000 {
		t.Fatalf("Wrong namespaced capability: %x", buf[:n])
	}
}

func TestUnpackMappedRealArchives(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Run the compiled test binary as root for actual user-namespace extraction")
	}
	for _, format := range []string{"tar", "squashfs"} {
		t.Run(format, func(t *testing.T) {
			base := t.TempDir() // root:root 0700 ancestor, inaccessible to mapped root.
			if err := os.Chmod(base, 0700); err != nil {
				t.Fatal(err)
			}
			name := makeMappedTestImage(t, base)
			if format == "squashfs" {
				source := filepath.Join(base, "source")
				if err := os.Mkdir(source, 0700); err != nil {
					t.Fatal(err)
				}
				if err := Unpack(name, source, false, 0, nil); err != nil {
					t.Fatal(err)
				}
				name = filepath.Join(base, "image.squashfs")
				out, err := exec.Command("mksquashfs", source, name, "-noappend", "-processors", "1", "-quiet").CombinedOutput()
				if err != nil {
					t.Fatalf("Build squashfs: %v: %s", err, out)
				}
			}
			dest := mappedTestOutput(t, base)
			if err := UnpackMapped(name, dest, 64*1024*1024, nil, testUnpackNamespace()); err != nil {
				t.Fatal(err)
			}
			checkMappedTestOutput(t, dest)
		})
	}
}

func TestUnpackMappedNeverFallsBackToHostRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Requires root")
	}
	base := t.TempDir()
	name := makeMappedTestImage(t, base)
	dest := filepath.Join(base, "output")
	if err := os.Mkdir(dest, 0700); err != nil {
		t.Fatal(err)
	}
	if err := UnpackMapped(name, dest, 0, nil, testUnpackNamespace()); err == nil {
		t.Fatal("Extraction unexpectedly succeeded into host-root-only directory")
	}
	entries, err := os.ReadDir(dest)
	if err != nil || len(entries) != 0 {
		t.Fatalf("Host-root output changed: %v", err)
	}
}

func TestUnpackMappedRejectsUnmappedArchiveOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Requires root")
	}
	base := t.TempDir()
	name := filepath.Join(base, "unmapped.tar")
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	w := tar.NewWriter(f)
	if err := w.WriteHeader(&tar.Header{Name: "outside-map", Typeflag: tar.TypeReg, Mode: 0600, Uid: 65536, Gid: 65536}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	dest := mappedTestOutput(t, base)
	if err := UnpackMapped(name, dest, 0, nil, testUnpackNamespace()); err == nil {
		t.Fatal("An unrepresentable image owner must fail the entire extraction")
	}
}

func TestUnpackMappedRejectsSymlinkEscape(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Requires root")
	}
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(outside, 1000000, 1000000); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "sentinel"), []byte("unchanged"), 0666); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(base, "escape.tar")
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	w := tar.NewWriter(f)
	for _, header := range []tar.Header{
		{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: "../outside", Mode: 0777},
		{Name: "escape/sentinel", Typeflag: tar.TypeReg, Mode: 0600},
	} {
		if err := w.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	dest := mappedTestOutput(t, base)
	if err := UnpackMapped(name, dest, 0, nil, testUnpackNamespace()); err == nil {
		t.Fatal("Symlink traversal must fail extraction")
	}
	data, err := os.ReadFile(filepath.Join(outside, "sentinel"))
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("Escape changed sibling: %q %v", data, err)
	}
}
