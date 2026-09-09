package drivers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/lxc/incus/v6/internal/linux"
	"github.com/lxc/incus/v6/internal/server/operations"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/subprocess"
	"github.com/lxc/incus/v6/shared/units"
)

// lustre uses local Incus scaffolding and separately owned canonical root generations.
type lustre struct {
	common
}

const lustreMagic = 0x0bd00bd0

// lustreAuthority is written by the platform, never inferred from an Incus database ID.
type lustreAuthority api.XlabRootAuthority

func (d *lustre) load() error {
	d.patches = map[string]func() error{
		"storage_lvm_skipactivation":                         nil,
		"storage_missing_snapshot_records":                   nil,
		"storage_delete_old_snapshot_records":                nil,
		"storage_zfs_drop_block_volume_filesystem_extension": nil,
		"storage_prefix_bucket_names_with_project":           nil,
	}
	_, err := exec.LookPath("lfs")
	return err
}

func (d *lustre) Info() Info {
	return Info{
		Name: "lustre", Version: "xlab-3", VolumeTypes: []VolumeType{VolumeTypeContainer},
		PreservesInodes: true, MountedRoot: true,
	}
}

func (d *lustre) FillConfig() error {
	if d.config["source"] == "" || !filepath.IsAbs(d.config["source"]) {
		return errors.New("Lustre source must be an explicitly mounted absolute path")
	}
	return lustreCanonicalUUID(d.config["lustre.host_id"])
}

func (d *lustre) Validate(config map[string]string) error {
	return d.validatePool(config, map[string]func(string) error{
		"lustre.host_id": lustreCanonicalUUID,
	}, nil)
}

func (d *lustre) Update(changed map[string]string) error {
	for key := range changed {
		if key == "source" || key == "lustre.host_id" {
			return fmt.Errorf("Cannot change Lustre pool identity %q", key)
		}
	}
	return nil
}

func lustreTrustedDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("Directory must be a clean absolute path")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("Untrusted Lustre control directory %q", current)
		}
		if current == "/" {
			return nil
		}
	}
}

func (d *lustre) checkSource() error {
	err := d.FillConfig()
	if err != nil {
		return err
	}
	err = lustreTrustedDirectory(d.config["source"])
	if err != nil {
		return err
	}
	var stat unix.Statfs_t
	err = unix.Statfs(d.config["source"], &stat)
	if err != nil {
		return err
	}
	if stat.Type != lustreMagic || stat.Flags&unix.ST_RDONLY != 0 {
		return errors.New("Source is not a writable Lustre filesystem")
	}
	return lustreCheckFlockMount(d.config["source"])
}

func lustreCheckFlockMount(source string) error {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	return lustreValidateFlockMount(source, string(raw))
}

func lustreValidateFlockMount(source, raw string) error {
	decode := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	found := false
	for _, line := range strings.Split(raw, "\n") {
		before, after, ok := strings.Cut(line, " - ")
		a, b := strings.Fields(before), strings.Fields(after)
		if !ok || len(a) < 6 || len(b) < 3 {
			continue
		}
		if decode.Replace(a[4]) != source {
			continue
		}
		if found || b[0] != "lustre" {
			return errors.New("Unexpected or stacked Lustre source mount")
		}
		found = true
		options := "," + a[5] + "," + b[2] + ","
		if strings.Contains(options, ",localflock,") || strings.Contains(options, ",noflock,") {
			return errors.New("Lustre root authority requires distributed flock")
		}
	}
	if !found {
		return errors.New("Lustre source must be the registered mountpoint")
	}
	return nil
}

// Hold a shared distributed lock throughout each root operation. The publisher
// takes the exclusive lock before replacing authority; this is not a runtime fence.
func (d *lustre) lockAuthority(vol Volume) (func(), error) {
	id, _, _, err := lustreVolumeIdentity(vol)
	if err != nil {
		return nil, err
	}
	if err := d.checkSource(); err != nil {
		return nil, err
	}
	return lustreLockAuthorityFile(filepath.Join(d.config["source"], "control", "roots", id+".lock"))
}

func lustreLockAuthorityFile(path string) (func(), error) {
	if err := lustreTrustedDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	// Only the publisher creates this stable inode. Never replace/recreate it.
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || info.Mode().Perm()&0o022 != 0 {
		file.Close()
		return nil, errors.New("Untrusted Lustre authority lock")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, err
	}
	return func() { file.Close() }, nil
}

func (d *lustre) Create() error {
	return d.checkSource()
}

func (d *lustre) Mount() (bool, error) {
	return false, d.checkSource()
}

func (d *lustre) Unmount() (bool, error) {
	return false, nil
}

// Delete does not own the shared namespace and must never wipe it.
func (d *lustre) Delete(op *operations.Operation) error {
	return lustreNoNestedMounts(GetPoolMountPath(d.name))
}

func (d *lustre) GetResources() (*api.ResourcesStoragePool, error) {
	err := d.checkSource()
	if err != nil {
		return nil, err
	}
	stat, err := linux.StatVFS(d.config["source"])
	if err != nil {
		return nil, err
	}
	res := &api.ResourcesStoragePool{}
	res.Space.Total = stat.Blocks * uint64(stat.Bsize)
	res.Space.Used = (stat.Blocks - stat.Bfree) * uint64(stat.Bsize)
	res.Inodes.Total = stat.Files
	res.Inodes.Used = stat.Files - stat.Ffree
	return res, nil
}

func lustreVolumeIdentity(vol Volume) (string, uint64, uint64, error) {
	id := vol.config["lustre.volume_id"]
	if vol.Type() != VolumeTypeContainer || vol.ContentType() != ContentTypeFS || vol.IsSnapshot() {
		return "", 0, 0, ErrNotSupported
	}
	err := lustreCanonicalUUID(id)
	if err != nil || strings.ToLower(id) != id {
		return "", 0, 0, errors.New("A canonical lowercase root volume UUID is required")
	}
	epoch, err := strconv.ParseUint(vol.config["lustre.owner_epoch"], 10, 64)
	if err != nil || epoch == 0 {
		return "", 0, 0, errors.New("A positive root owner epoch is required")
	}
	generation, err := strconv.ParseUint(vol.config["lustre.generation"], 10, 64)
	if err != nil || generation == 0 {
		return "", 0, 0, errors.New("A positive root generation is required")
	}
	return id, epoch, generation, nil
}

func (d *lustre) ValidateVolume(vol Volume, removeUnknownKeys bool) error {
	_, _, _, err := lustreVolumeIdentity(vol)
	if err != nil {
		return err
	}
	return d.validateVolume(vol, map[string]func(string) error{
		"lustre.volume_id":   lustreCanonicalUUID,
		"lustre.owner_epoch": lustrePositiveUint,
		"lustre.generation":  lustrePositiveUint,
	}, removeUnknownKeys)
}

func lustreCanonicalUUID(value string) error {
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil || id.String() != value {
		return errors.New("Canonical nonzero UUID required")
	}
	return nil
}

func lustrePositiveUint(value string) error {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n == 0 {
		return errors.New("Positive integer required")
	}
	return nil
}

func lustreReadJSON(path string, value any) error {
	err := lustreTrustedDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Nlink != 1 || info.Mode().Perm()&0o022 != 0 || info.Size() > 65536 {
		return errors.New("Untrusted Lustre authority file")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(value)
	if err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("Trailing content in Lustre authority file")
	}
	return nil
}

func (a lustreAuthority) validateIdentity(id string, host string, epoch uint64, generation uint64, instanceName string) error {
	if err := a.IDMap.Validate(); err != nil {
		return err
	}
	if a.Version != 3 || a.Revision == 0 || a.VolumeID != id || a.OwnerID != host || a.Epoch != epoch || a.Generation != generation {
		return errors.New("Lustre root authority does not match volume, host, epoch and generation")
	}
	if lustreCanonicalUUID(a.InstanceID) != nil {
		return errors.New("Root authority requires a canonical instance UUID")
	}
	// Xlab uses default-project names derived from the platform instance UUID.
	// A second project/name must not adopt an already allocated canonical root.
	expectedName := "tc-" + strings.ReplaceAll(a.InstanceID, "-", "")[:12]
	if instanceName != expectedName {
		return errors.New("Root authority belongs to another Incus instance name or project")
	}
	if a.ProjectID == 0 || a.QuotaBytes <= 0 || a.QuotaBytes%1024 != 0 || a.QuotaInodes <= 0 {
		return errors.New("Lustre root requires an allocated project and positive hard limits")
	}
	return nil
}

func (a lustreAuthority) validate(id string, host string, epoch uint64, generation uint64, instanceName string) error {
	if err := a.validateIdentity(id, host, epoch, generation, instanceName); err != nil {
		return err
	}
	if a.Phase != "creating" && a.Phase != "attached" && a.Phase != "destroy" {
		return errors.New("Lustre root has no active authority")
	}
	return nil
}

func (d *lustre) readAuthority(vol Volume) (*lustreAuthority, string, error) {
	id, epoch, generation, err := lustreVolumeIdentity(vol)
	if err != nil {
		return nil, "", err
	}
	err = d.checkSource()
	if err != nil {
		return nil, "", err
	}
	var authority lustreAuthority
	err = lustreReadJSON(filepath.Join(d.config["source"], "control", "roots", id+".json"), &authority)
	if err != nil {
		return nil, "", err
	}
	err = authority.validateIdentity(id, d.config["lustre.host_id"], epoch, generation, vol.name)
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(d.config["source"], "roots", id, "generations", strconv.FormatUint(generation, 10))
	return &authority, path, nil
}

func (d *lustre) authority(vol Volume) (*lustreAuthority, string, error) {
	a, path, err := d.readAuthority(vol)
	if err != nil {
		return nil, "", err
	}
	if a.Phase != "creating" && a.Phase != "attached" && a.Phase != "destroy" {
		return nil, "", errors.New("Lustre root has no active authority")
	}
	return a, path, nil
}

func (d *lustre) VolumeSnapshots(vol Volume, op *operations.Operation) ([]string, error) {
	return []string{}, nil
}

func (d *lustre) ListVolumes() ([]Volume, error) {
	return genericVFSListVolumes(d)
}

func (d *lustre) HasVolume(vol Volume) (bool, error) {
	_, path, err := d.authority(vol)
	if err != nil {
		return false, err
	}
	_, err = os.Lstat(filepath.Join(path, "rootfs"))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func (d *lustre) quota(vol Volume, set bool) (int64, error) {
	authority, path, err := d.authority(vol)
	if err != nil {
		return 0, err
	}
	return lustreQuota(authority, path, d.config["source"], set)
}

// Callers must hold and validate the current authority before quota read/write.
func lustreQuota(authority *lustreAuthority, path, source string, set bool) (int64, error) {
	err := lustreTrustedDirectory(path)
	if err != nil {
		return 0, err
	}
	project := strconv.FormatUint(uint64(authority.ProjectID), 10)
	out, err := subprocess.RunCommandCLocale("lfs", "project", "-d", path)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(out)
	if len(fields) < 2 || fields[0] != project || fields[1] != "P" {
		return 0, errors.New("Root project identity or inheritance differs from allocation")
	}
	if set {
		_, err = subprocess.RunCommandCLocale("lfs", "setquota", "-p", project, "-B", strconv.FormatInt(authority.QuotaBytes/1024, 10)+"K", "-I", strconv.FormatInt(authority.QuotaInodes, 10), source)
		if err != nil {
			return 0, err
		}
	}
	out, err = subprocess.RunCommandCLocale("lfs", "quota", "-p", project, source)
	if err != nil {
		return 0, err
	}
	used, bytes, inodes, err := lustreParseQuota(out)
	if err != nil {
		return 0, err
	}
	if bytes != authority.QuotaBytes || inodes != authority.QuotaInodes {
		return 0, errors.New("Root hard quota differs from allocated limits")
	}
	return used, nil
}

func lustreParseQuota(out string) (int64, int64, int64, error) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "/") {
			fields = fields[1:]
		}
		if len(fields) != 8 {
			continue
		}
		used, e1 := strconv.ParseInt(strings.TrimSuffix(fields[0], "*"), 10, 64)
		blocks, e2 := strconv.ParseInt(fields[2], 10, 64)
		inodes, e3 := strconv.ParseInt(fields[6], 10, 64)
		if e1 == nil && e2 == nil && e3 == nil && used >= 0 && used <= (1<<63-1)/1024 && blocks > 0 && blocks <= (1<<63-1)/1024 && inodes > 0 {
			return used * 1024, blocks * 1024, inodes, nil
		}
	}
	return 0, 0, 0, errors.New("Cannot read Lustre project quota totals")
}

func (d *lustre) GetVolumeUsage(vol Volume) (int64, error) {
	return d.quota(vol, false)
}

func (d *lustre) SetVolumeQuota(vol Volume, size string, allowUnsafeResize bool, op *operations.Operation) error {
	unlock, err := d.lockAuthority(vol)
	if err != nil {
		return err
	}
	defer unlock()
	authority, _, err := d.authority(vol)
	if err != nil {
		return err
	}
	requested, err := units.ParseByteSizeString(size)
	if err != nil || requested != authority.QuotaBytes || authority.Phase == "destroy" {
		return errors.New("Quota update requires matching platform allocation")
	}
	_, err = d.quota(vol, true)
	return err
}

func (d *lustre) UpdateVolume(vol Volume, changed map[string]string) error {
	for key := range changed {
		if strings.HasPrefix(key, "lustre.") {
			return errors.New("Root identity requires an explicit ownership transition")
		}
	}
	return d.updateVolume(vol, changed)
}
