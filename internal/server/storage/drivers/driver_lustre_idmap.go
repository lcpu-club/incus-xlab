package drivers

import (
	"errors"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/idmap"
)

func lustreDiskIDMap(m api.XlabRootIDMap) (*idmap.Set, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	base, user := int64(m.Base), int64(m.UserID)
	entries := []idmap.Entry{
		{IsUID: true, IsGID: true, HostID: base, NSID: 0, MapRange: user},
		{IsUID: true, IsGID: true, HostID: user, NSID: user, MapRange: 1},
	}
	if user+1 < 65536 {
		entries = append(entries, idmap.Entry{IsUID: true, IsGID: true, HostID: base + user + 1, NSID: user + 1, MapRange: 65536 - user - 1})
	}
	return &idmap.Set{Entries: entries}, nil
}

// RootDiskIDMap reads only controller-authorized identity. Creation callers hold
// the enclosing creation lock through extraction; completed roots additionally
// bind the same map in their durable ready record.
func (d *lustre) RootDiskIDMap(vol Volume, requireReady bool) (*idmap.Set, error) {
	unlock, err := d.lockAuthority(vol)
	if err != nil {
		return nil, err
	}
	defer unlock()
	a, path, err := d.authority(vol)
	if err != nil {
		return nil, err
	}
	if a.Phase == "destroy" {
		return nil, errors.New("Cannot use the ID map of a root authorized for destruction")
	}
	if requireReady {
		if err := lustreCheckReady(a, path); err != nil {
			return nil, err
		}
	} else if a.Phase != "creating" {
		return nil, errors.New("Image extraction requires creating authority")
	}
	return lustreDiskIDMap(a.IDMap)
}

// ImageUnpackIDMap returns nil for unchanged generic backends. Lustre must supply
// its authoritative disk map; missing state is an error, never host-root fallback.
func (v Volume) ImageUnpackIDMap() (*idmap.Set, error) {
	if v.driver == nil || v.driver.Info().Name != "lustre" {
		return nil, nil
	}
	driver, ok := v.driver.(interface {
		RootDiskIDMap(Volume, bool) (*idmap.Set, error)
	})
	if !ok {
		return nil, errors.New("Lustre driver lacks persistent image ID mapping")
	}
	return driver.RootDiskIDMap(v, false)
}
