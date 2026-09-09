package drivers

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/archive"
	"github.com/stretchr/testify/require"
)

func TestLustrePersistentDiskIDMap(t *testing.T) {
	for _, user := range []uint32{10000, 65535} {
		m, err := lustreDiskIDMap(api.XlabRootIDMap{Base: 1000000, UserID: user})
		require.NoError(t, err)
		n := archive.UnpackNamespace{UID: m.ToUIDMappings(), GID: m.ToGIDMappings()}
		require.NoError(t, n.Validate())
		uid, gid := m.ShiftIntoNS(0, 0)
		require.EqualValues(t, 1000000, uid)
		require.EqualValues(t, 1000000, gid)
		uid, gid = m.ShiftIntoNS(int64(user), int64(user))
		require.EqualValues(t, user, uid)
		require.EqualValues(t, user, gid)
	}
}

func TestLustreReadyBindsDiskIDMap(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Requires trusted root-owned test ancestors")
	}
	base, err := os.MkdirTemp("/root", "xlab-ready-idmap-")
	require.NoError(t, err)
	defer os.RemoveAll(base)
	path := filepath.Join(base, "1")
	a := &lustreAuthority{IDMap: api.XlabRootIDMap{Base: 1000000, UserID: 10000}, VolumeID: "79072040-6cec-4789-a6c9-ebbdfe93b935", Generation: 1, ProjectID: 1000100}
	require.NoError(t, lustreWriteReady(a, path))
	require.NoError(t, lustreCheckReady(a, path))
	a.IDMap.Base += 65536
	require.Error(t, lustreCheckReady(a, path))
	a.IDMap.Base -= 65536
	a.IDMap.UserID++
	require.Error(t, lustreCheckReady(a, path))
}

func TestLustreAuthorityRejectsStaleWriters(t *testing.T) {
	const volume = "79072040-6cec-4789-a6c9-ebbdfe93b935"
	const host = "15594190-9b9e-4b68-8cda-51a1ff48187f"
	authority := lustreAuthority{
		Version: 3, IDMap: api.XlabRootIDMap{Base: 1000000, UserID: 10000}, Revision: 1, InstanceID: "8b1d8bb1-8aac-45e9-a379-342f047e09a5", VolumeID: volume, OwnerID: host, Epoch: 7, Generation: 3,
		ProjectID: 1000100, QuotaBytes: 10 * 1024 * 1024, QuotaInodes: 1000, Phase: "attached",
	}
	require.NoError(t, authority.validate(volume, host, 7, 3, "tc-8b1d8bb18aac"))
	for _, name := range []string{"another-root", "otherproject_tc-8b1d8bb18aac", "tc-8b1d8bb18aad"} {
		require.Error(t, authority.validate(volume, host, 7, 3, name))
	}
	for _, mutation := range []func(*lustreAuthority){
		func(a *lustreAuthority) { a.OwnerID = "old-host" },
		func(a *lustreAuthority) { a.VolumeID = "another-volume" },
		func(a *lustreAuthority) { a.Epoch-- },
		func(a *lustreAuthority) { a.Generation-- },
		func(a *lustreAuthority) { a.Phase = "released" },
		func(a *lustreAuthority) { a.ProjectID = 0 },
		func(a *lustreAuthority) { a.QuotaBytes = 0 },
		func(a *lustreAuthority) { a.QuotaBytes++ },
		func(a *lustreAuthority) { a.QuotaInodes = 0 },
		func(a *lustreAuthority) { a.Version++ },
		func(a *lustreAuthority) { a.Revision = 0 },
		func(a *lustreAuthority) { a.InstanceID = "../another-root" },
	} {
		changed := authority
		mutation(&changed)
		require.Error(t, changed.validate(volume, host, 7, 3, "tc-8b1d8bb18aac"))
	}
}

func TestLustreQuotaTotals(t *testing.T) {
	for _, out := range []string{
		"Disk quotas for prj 1000100:\nFilesystem kbytes quota limit grace files quota limit grace\n/srv/xlab 12 0 10240 - 4 0 1000 -\n",
		"Disk quotas for prj 1000100:\n/srv/long-path\n 12* 0 10240 - 4 0 1000 -\n",
	} {
		used, bytes, inodes, err := lustreParseQuota(out)
		require.NoError(t, err)
		require.EqualValues(t, 12*1024, used)
		require.EqualValues(t, 10240*1024, bytes)
		require.EqualValues(t, 1000, inodes)
	}
	for _, out := range []string{
		"quota failed", "/srv/xlab 12 0 0 - 4 0 1000 -", "/srv/xlab 12 0 10240 - 4 0 0 -",
		"/srv/xlab 12 0 9223372036854775807 - 4 0 1000 -",
	} {
		_, _, _, err := lustreParseQuota(out)
		require.Error(t, err)
	}
}

func TestLustreRejectsUnallocatedVolumeIdentity(t *testing.T) {
	config := map[string]string{
		"lustre.volume_id":   "79072040-6cec-4789-a6c9-ebbdfe93b935",
		"lustre.owner_epoch": "7", "lustre.generation": "3",
	}
	vol := NewVolume(&lustre{}, "test", VolumeTypeContainer, ContentTypeFS, "test", config, nil)
	_, _, _, err := lustreVolumeIdentity(vol)
	require.NoError(t, err)
	for _, key := range []string{"lustre.volume_id", "lustre.owner_epoch", "lustre.generation"} {
		saved := config[key]
		config[key] = "../../another-root"
		_, _, _, err = lustreVolumeIdentity(vol)
		require.Error(t, err)
		config[key] = saved
	}
	vol.volType = VolumeTypeVM
	_, _, _, err = lustreVolumeIdentity(vol)
	require.ErrorIs(t, err, ErrNotSupported)
}

func TestLustrePoolDoesNotAcceptLocalFallback(t *testing.T) {
	d := &lustre{common: common{config: map[string]string{
		"source": "/", "lustre.host_id": "15594190-9b9e-4b68-8cda-51a1ff48187f",
	}}}
	require.Error(t, d.Create())
	_, err := d.Mount()
	require.Error(t, err)
	_, err = d.GetResources()
	require.Error(t, err)
}

func TestLustreDistributedFlockRequired(t *testing.T) {
	line := "38 25 0:38 / /srv/xlab rw,relatime - lustre server:/Lustre01/xlab rw,flock\n"
	require.NoError(t, lustreValidateFlockMount("/srv/xlab", line))
	for _, raw := range []string{
		strings.ReplaceAll(line, "rw,flock", "rw,localflock"),
		strings.ReplaceAll(line, "rw,flock", "rw,noflock"),
		strings.ReplaceAll(line, " - lustre ", " - ext4 "),
		line + line,
		"",
	} {
		require.Error(t, lustreValidateFlockMount("/srv/xlab", raw))
	}
}

func TestLustreOperationLockExcludesPublisher(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned fixture ancestors")
	}
	dir, err := os.MkdirTemp("/root", "xlab-incus-lock-test-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "root.lock")
	publisher, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	require.NoError(t, err)
	defer publisher.Close()
	unlock, err := lustreLockAuthorityFile(path)
	require.NoError(t, err)
	require.ErrorIs(t, unix.Flock(int(publisher.Fd()), unix.LOCK_EX|unix.LOCK_NB), unix.EWOULDBLOCK)
	unlock()
	require.NoError(t, unix.Flock(int(publisher.Fd()), unix.LOCK_EX|unix.LOCK_NB))
	_, err = lustreLockAuthorityFile(path)
	require.ErrorIs(t, err, unix.EWOULDBLOCK)
	require.NoError(t, unix.Flock(int(publisher.Fd()), unix.LOCK_UN))
	require.NoError(t, os.Remove(path))
	_, err = lustreLockAuthorityFile(path)
	require.Error(t, err) // driver must not recreate missing control state
}

func TestLustreReleaseMatchesExactAuthority(t *testing.T) {
	a := lustreAuthority{Version: 3, IDMap: api.XlabRootIDMap{Base: 1000000, UserID: 10000}, Revision: 9, VolumeID: "79072040-6cec-4789-a6c9-ebbdfe93b935", InstanceID: "8b1d8bb1-8aac-45e9-a379-342f047e09a5", OwnerID: "15594190-9b9e-4b68-8cda-51a1ff48187f", Epoch: 2, Generation: 1, ProjectID: 1000100, QuotaBytes: 1048576, QuotaInodes: 1000, Phase: "releasing"}
	req := api.XlabRootReleaseRequest{VolumeID: a.VolumeID, InstanceID: a.InstanceID, OwnerID: a.OwnerID, Epoch: a.Epoch, Generation: a.Generation, Revision: a.Revision}
	require.NoError(t, a.checkRelease(req))
	for _, mutate := range []func(*api.XlabRootReleaseRequest){
		func(r *api.XlabRootReleaseRequest) { r.Revision-- },
		func(r *api.XlabRootReleaseRequest) { r.Epoch-- },
		func(r *api.XlabRootReleaseRequest) { r.Generation++ },
		func(r *api.XlabRootReleaseRequest) { r.VolumeID = r.InstanceID },
		func(r *api.XlabRootReleaseRequest) { r.InstanceID = r.OwnerID },
		func(r *api.XlabRootReleaseRequest) { r.OwnerID = r.VolumeID },
	} {
		bad := req
		mutate(&bad)
		require.Error(t, a.checkRelease(bad))
	}
	for _, phase := range []string{"creating", "attached", "released", "destroy"} {
		a.Phase = phase
		require.Error(t, a.checkRelease(req))
	}
}

func TestLustreReleaseDetectsBindAliases(t *testing.T) {
	pool := "/srv/xlab"
	generation := pool + "/roots/uuid/generations/1"
	parent := "38 25 0:38 /xlab /srv/xlab rw - lustre mgs:/Lustre01 rw,flock\n"
	require.NoError(t, lustreCheckDetached(pool, generation, parent))
	for _, aliasRoot := range []string{"/xlab/roots/uuid/generations/1", "/xlab/roots/uuid/generations/1/rootfs/home"} {
		require.Error(t, lustreCheckDetached(pool, generation, parent+"39 25 0:38 "+aliasRoot+" /unexpected/alias rw - lustre mgs:/Lustre01 rw\n"))
	}
	require.NoError(t, lustreCheckDetached(pool, generation, parent+"39 25 0:38 /xlab/roots/uuid/generations/10 /another/root rw - lustre mgs:/Lustre01 rw\n"))
	for _, raw := range []string{"", "malformed", parent + parent} {
		require.Error(t, lustreCheckDetached(pool, generation, raw))
	}
	require.Error(t, lustreCheckDetached(pool, "/another/pool/root", parent))
}

func TestLustreReleaseCannotQuiesceLocalFallback(t *testing.T) {
	d := &lustre{common: common{config: map[string]string{"source": "/", "lustre.host_id": "15594190-9b9e-4b68-8cda-51a1ff48187f"}}}
	vol := NewVolume(d, "test", VolumeTypeContainer, ContentTypeFS, "tc-8b1d8bb18aac", map[string]string{"lustre.volume_id": "79072040-6cec-4789-a6c9-ebbdfe93b935", "lustre.owner_epoch": "1", "lustre.generation": "1"}, nil)
	_, err := d.ReleaseRoot(vol, api.XlabRootReleaseRequest{}, func() error { t.Fatal("stopped before backend authority validation"); return nil }, nil)
	require.Error(t, err)
}
