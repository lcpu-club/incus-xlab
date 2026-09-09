package drivers

import (
	"errors"
	"os"
	"path/filepath"

	liblxc "github.com/lxc/go-lxc"
)

func (d *lxc) saveLXCConfig(cc *liblxc.Container, path string) error {
	if d.storagePool == nil || d.storagePool.Driver().Info().Name != "lustre" {
		return cc.SaveConfigFile(path)
	}

	d.cMu.Lock()
	defer d.cMu.Unlock()
	return saveLXCConfigDetached(cc, path)
}

// liblxc 5.0 save_config calls create_container_dir even with an alternate
// output file. That chowns config_path/name to the mapped root. Serialize in
// disposable local scaffolding instead of modifying the shared generation.
// Restore the runtime's original identity before returning, including on errors.
func saveLXCConfigDetached(cc *liblxc.Container, path string) (err error) {
	dir, err := os.MkdirTemp(filepath.Dir(path), ".lxc-config-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()

	original := cc.ConfigPath()
	err = cc.SetConfigPath(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cc.SetConfigPath(original)) }()
	return cc.SaveConfigFile(path)
}
