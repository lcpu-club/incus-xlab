package drivers

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	liblxc "github.com/lxc/go-lxc"
)

func TestSaveLXCConfigPreservesGenerationOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for liblxc mapped directory ownership")
	}
	dir := t.TempDir()
	name := "test-xlab-save"
	generation := filepath.Join(dir, name)
	if err := os.Mkdir(generation, 0o711); err != nil {
		t.Fatal(err)
	}
	cc, err := liblxc.NewContainer(name, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Release()
	for _, mapping := range []string{"u 0 100000000 65536", "g 0 100000000 65536"} {
		if err := cc.SetConfigItem("lxc.idmap", mapping); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "lxc.conf")
	if err := saveLXCConfigDetached(cc, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "u 0 100000000 65536") || !strings.Contains(string(data), "g 0 100000000 65536") {
		t.Fatalf("map was lost: %s, %v", data, err)
	}
	// Failure must restore the original runtime identity as well.
	if err := saveLXCConfigDetached(cc, generation); err == nil {
		t.Fatal("saving a config over a directory succeeded")
	}
	if cc.ConfigPath() != dir {
		t.Fatal("runtime identity was not restored")
	}
	st, err := os.Stat(generation)
	if err != nil {
		t.Fatal(err)
	}
	owner := st.Sys().(*syscall.Stat_t)
	if owner.Uid != 0 || owner.Gid != 0 || st.Mode().Perm() != 0o711 {
		t.Fatalf("generation owner or permissions changed: %+v", st)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".lxc-config-*"))
	if len(leftovers) != 0 {
		t.Fatalf("leftover serialization directories: %v", leftovers)
	}
}
