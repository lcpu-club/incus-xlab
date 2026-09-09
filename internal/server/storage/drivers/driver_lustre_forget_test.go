package drivers

import (
	"testing"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/stretchr/testify/require"
)

func TestLustreForgetRejectsStaleAndReturnedOwnership(t *testing.T) {
	source := "15594190-9b9e-4b68-8cda-51a1ff48187f"
	current := lustreAuthority{Version: 4, Revision: 6, VolumeID: "79072040-6cec-4789-a6c9-ebbdfe93b935", InstanceID: "6c646b17-4189-43e9-a98c-5a7cf24de048", OwnerID: "b7487aa2-133c-419b-a5bd-039bc1fcb47f", Epoch: 2, Generation: 1, Phase: "attached", ProjectID: 1000100, QuotaBytes: 1024, QuotaInodes: 10, IDMap: api.XlabRootIDMap{Base: 100000000, LeaseID: "51609467-1037-4876-97b9-02e9dd47138c", GuestUID: 10000, GuestGID: 10000, BackendUID: 100100000, BackendGID: 100100000}}
	req := api.XlabRootForgetRequest{XlabRootInspectionRequest: api.XlabRootInspectionRequest{Authority: api.XlabRootAuthority(current), Pool: "xlab", Source: "/srv/xlab"}, FormerOwnerID: source, FormerEpoch: 1, RootFID: "[0x200000401:0x123:0x0]"}
	require.NoError(t, current.checkForget(req, source, 1))
	for _, mutate := range []func(*lustreAuthority){
		func(a *lustreAuthority) { a.Revision++ },
		func(a *lustreAuthority) { a.Generation++ },
		func(a *lustreAuthority) { a.Epoch++ },
		func(a *lustreAuthority) { a.OwnerID = source; a.Epoch = 3; a.Revision = 10 },
		func(a *lustreAuthority) { a.Phase = "releasing" },
	} {
		a := current
		mutate(&a)
		require.Error(t, a.checkForget(req, source, 1))
	}
	require.Error(t, current.checkForget(req, current.OwnerID, 1))
	require.Error(t, current.checkForget(req, source, 2))
	// Even a matching current grant cannot remove its own local metadata.
	returned := current
	returned.OwnerID = source
	returned.Epoch = 3
	req.Authority = api.XlabRootAuthority(returned)
	req.FormerEpoch = 2
	require.Error(t, returned.checkForget(req, source, 2))
}
