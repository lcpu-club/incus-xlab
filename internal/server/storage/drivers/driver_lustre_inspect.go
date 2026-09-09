package drivers

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/idmap"
	"github.com/lxc/incus/v6/shared/subprocess"
)

var lustreFIDPattern = regexp.MustCompile(`^\[0x(?:0|[1-9a-f][0-9a-f]{0,15}):0x(?:0|[1-9a-f][0-9a-f]{0,7}):0x(?:0|[1-9a-f][0-9a-f]{0,7})\]$`)

func lustreParseFID(output string) (string, error) {
	fid := strings.TrimSpace(output)
	if !lustreFIDPattern.MatchString(fid) || fid == "[0x0:0x0:0x0]" {
		return "", errors.New("Invalid Lustre root FID")
	}
	return fid, nil
}

// InspectRoot never repairs, mounts or changes a volume. A missing completion
// record, changed identity or unavailable backend yields no ready observation.
func (d *lustre) InspectRoot(vol Volume, req api.XlabRootInspectionRequest, checkMap func(*idmap.Set) error) (*api.XlabRootInspection, error) {
	unlock, err := d.lockAuthority(vol)
	if err != nil {
		return nil, err
	}
	defer unlock()
	a, path, err := d.authority(vol)
	if err != nil {
		return nil, err
	}
	if *a != lustreAuthority(req.Authority) || req.Pool != vol.Pool() || req.Source != d.config["source"] || (a.Phase != "creating" && a.Phase != "attached") {
		return nil, errors.New("Root inspection does not match current authority and pool binding")
	}
	if err := lustreCheckReady(a, path); err != nil {
		return nil, err
	}
	if err := lustreNoNestedMounts(path); err != nil {
		return nil, err
	}
	if _, err := d.quota(vol, false); err != nil {
		return nil, err
	}
	want, err := lustreDiskIDMap(a.IDMap)
	if err != nil {
		return nil, err
	}
	if checkMap == nil {
		return nil, errors.New("Root inspection requires runtime identity validation")
	}
	if err := checkMap(want); err != nil {
		return nil, err
	}
	root := filepath.Join(path, "rootfs")
	fid, err := lustreRootFID(root)
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
	return &api.XlabRootInspection{XlabRootInspectionRequest: api.XlabRootInspectionRequest{Authority: api.XlabRootAuthority(*a), Pool: vol.Pool(), Source: d.config["source"]}, BootID: bootID, RootFID: fid, Ready: true, IDMapMatches: true}, nil
}

func lustreRootFID(root string) (string, error) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return "", errors.New("Rootfs is missing or is not a real directory")
	}
	output, err := subprocess.RunCommandCLocale("lfs", "path2fid", root)
	if err != nil {
		return "", err
	}
	return lustreParseFID(output)
}
