package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Local filesystem test only: it does not stand in for native DB or Lustre IO.
func TestRootForgetLocalPathsRetainData(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Requires trusted root-owned fixture ancestors")
	}
	base, err := os.MkdirTemp("/root", "xlab-forget-")
	require.NoError(t, err)
	defer os.RemoveAll(base)
	for _, scenario := range []string{"ok", "relative", "wrong-link", "nonempty", "mount-symlink", "overlap", "untrusted-parent"} {
		t.Run(scenario, func(t *testing.T) {
			dir := filepath.Join(base, scenario)
			require.NoError(t, os.Mkdir(dir, 0700))
			source := filepath.Join(dir, "shared")
			require.NoError(t, os.Mkdir(source, 0700))
			payload := filepath.Join(source, "root-data")
			require.NoError(t, os.WriteFile(payload, []byte("retained root"), 0600))
			before, err := os.Stat(payload)
			require.NoError(t, err)
			mount, link := filepath.Join(dir, "mount"), filepath.Join(dir, "instance")
			require.NoError(t, os.Mkdir(mount, 0700))
			target := mount
			switch scenario {
			case "relative":
				target = "mount"
			case "wrong-link":
				target = source
			case "nonempty":
				require.NoError(t, os.WriteFile(filepath.Join(mount, "keep"), []byte("local data"), 0600))
			case "mount-symlink":
				require.NoError(t, os.Remove(mount))
				require.NoError(t, os.Symlink(source, mount))
			case "overlap":
				mount = filepath.Join(source, "mount")
				target = mount
				require.NoError(t, os.Mkdir(mount, 0700))
			case "untrusted-parent":
				require.NoError(t, os.Chmod(dir, 0777))
			}
			require.NoError(t, os.Symlink(target, link))
			err = rootForgetLocalPaths(link, mount, source)
			if scenario == "ok" || scenario == "relative" {
				require.NoError(t, err)
				_, err = os.Lstat(link)
				require.True(t, os.IsNotExist(err))
				_, err = os.Lstat(mount)
				require.True(t, os.IsNotExist(err))
				require.NoError(t, rootForgetLocalPaths(link, mount, source)) // Retry after partial response loss.
			} else {
				require.Error(t, err)
				_, err = os.Lstat(link)
				require.NoError(t, err) // Validation before mutation.
				_, err = os.Lstat(mount)
				require.NoError(t, err)
			}
			after, err := os.Stat(payload)
			require.NoError(t, err)
			require.True(t, os.SameFile(before, after))
			data, err := os.ReadFile(payload)
			require.NoError(t, err)
			require.Equal(t, "retained root", string(data))
		})
	}
}
