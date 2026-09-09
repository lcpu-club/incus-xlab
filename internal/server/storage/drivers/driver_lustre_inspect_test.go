package drivers

import (
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/idmap"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestLustreInspectionFID(t *testing.T) {
	for _, raw := range []string{"[0x200000401:0x123:0x0]", "[0xffffffffffffffff:0xffffffff:0xffffffff]\n"} {
		fid, err := lustreParseFID(raw)
		require.NoError(t, err)
		require.NotEmpty(t, fid)
	}
	for _, raw := range []string{"", "[0x0:0x0:0x0]", "[0x00:0x0:0x0]", "[0x200000401:0x123:0x0]\n[0x200000401:0x124:0x0]", "[0x10000000000000000:0x1:0x0]", "[0x1:0x100000000:0x0]", "[0x1:0x2:0x100000000]", "0x1:0x2:0x0", "[0xA:0x1:0x0]"} {
		_, err := lustreParseFID(raw)
		require.Error(t, err, raw)
	}
}

func TestLustreInspectionNeverFallsBackToLocalFS(t *testing.T) {
	d := &lustre{common: common{config: map[string]string{"source": "/", "lustre.host_id": "15594190-9b9e-4b68-8cda-51a1ff48187f"}}}
	vol := NewVolume(d, "xlab", VolumeTypeContainer, ContentTypeFS, "tc-8b1d8bb18aac", map[string]string{"lustre.volume_id": "79072040-6cec-4789-a6c9-ebbdfe93b935", "lustre.owner_epoch": "1", "lustre.generation": "1"}, nil)
	called := false
	result, err := d.InspectRoot(vol, api.XlabRootInspectionRequest{}, func(*idmap.Set) error { called = true; return nil })
	require.Error(t, err)
	require.Nil(t, result)
	require.False(t, called)
}

func TestLustreStartRequiresAttachedPublication(t *testing.T) {
	for _, phase := range []string{"creating", "attached", "releasing", "released", "destroy", ""} {
		a := lustreAuthority{Phase: phase}
		if phase == "attached" {
			require.NoError(t, a.checkStart())
		} else {
			require.Error(t, a.checkStart())
		}
	}
}
