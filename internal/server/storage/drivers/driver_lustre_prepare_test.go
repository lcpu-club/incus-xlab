package drivers

import (
	"github.com/lxc/incus/v6/shared/api"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestLustrePreparationRequiresCurrentForeignRoot(t *testing.T) {
	source, target := "15594190-9b9e-4b68-8cda-51a1ff48187f", "b7487aa2-133c-419b-a5bd-039bc1fcb47f"
	a := lustreAuthority{Version: 3, OwnerID: source, Epoch: 1, Generation: 1, Revision: 2, Phase: "attached"}
	r := api.XlabRootPrepareRequest{XlabRootInspectionRequest: api.XlabRootInspectionRequest{Authority: api.XlabRootAuthority(a)}, TargetOwnerID: target, OperationID: "79072040-6cec-4789-a6c9-ebbdfe93b935", Architecture: "aarch64"}
	require.NoError(t, a.checkPrepare(r, target, "aarch64"))
	require.Error(t, a.checkPrepare(r, source, "aarch64"))
	require.Error(t, a.checkPrepare(r, target, "x86_64"))
	for _, mutate := range []func(*api.XlabRootPrepareRequest){
		func(r *api.XlabRootPrepareRequest) { r.Authority.Revision++ },
		func(r *api.XlabRootPrepareRequest) { r.Authority.Epoch++ },
		func(r *api.XlabRootPrepareRequest) { r.Authority.Phase = "creating" },
		func(r *api.XlabRootPrepareRequest) { r.TargetOwnerID = source },
		func(r *api.XlabRootPrepareRequest) { r.OperationID = "invalid" },
	} {
		bad := r
		mutate(&bad)
		require.Error(t, a.checkPrepare(bad, target, "aarch64"))
	}
	a.Phase = "released"
	r.Authority = api.XlabRootAuthority(a)
	require.Error(t, a.checkPrepare(r, target, "aarch64"))
}
