package main

import (
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/util"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func rootAdoptFixture() (string, api.XlabRootAdoptRequest) {
	id := "8b1d8bb1-8aac-45e9-a379-342f047e09a5"
	m := &api.XlabRootMetadata{Version: 1, Architecture: "aarch64", CreatedAt: time.Unix(1700000000, 0).UTC(), Config: map[string]string{
		"user.tc.id": id, "user.tc.managed": "true", "volatile.uuid": "15594190-9b9e-4b68-8cda-51a1ff48187f", "volatile.uuid.generation": "79072040-6cec-4789-a6c9-ebbdfe93b935", "volatile.cloud-init.instance-id": "keep-cloud-init-id", "volatile.idmap.next": "[]", "volatile.last_state.idmap": "[]", "volatile.eth0.host_name": "source-veth", "volatile.eth0.hwaddr": "00:16:3e:01:02:03", "volatile.last_state.power": "STOPPED", "cloud-init.user-data": "keep source user data",
	}, Devices: map[string]map[string]string{
		"root":    {"type": "disk", "path": "/", "pool": "source-pool", "size": "1024", "initial.lustre.owner_epoch": "1"},
		"eth0":    {"type": "nic", "nictype": "bridged", "parent": "source-br"},
		"fs-home": {"type": "disk", "path": "/home/student", "source": "/srv/source/home"},
	}}
	return "tc-8b1d8bb18aac", api.XlabRootAdoptRequest{Target: api.XlabRootInspectionRequest{Authority: api.XlabRootAuthority{InstanceID: id, VolumeID: "79072040-6cec-4789-a6c9-ebbdfe93b935", Epoch: 2, Generation: 1, QuotaBytes: 1024}, Pool: "target-pool", Source: "/srv/xlab"}, Release: api.XlabRootRelease{Metadata: m}, Bridge: "target-br"}
}

func TestRootAdoptionPreservesGuestIdentityAndTemplateState(t *testing.T) {
	for _, trigger := range []string{"", "create", "copy"} {
		name, req := rootAdoptFixture()
		if trigger != "" {
			req.Release.Metadata.Config["volatile.apply_template"] = trigger
		}
		args, err := rootAdoptArgs(name, req)
		require.NoError(t, err)
		for _, key := range []string{"volatile.uuid", "volatile.uuid.generation", "volatile.cloud-init.instance-id", "volatile.idmap.next", "volatile.last_state.idmap", "volatile.apply_template", "cloud-init.user-data"} {
			require.Equal(t, req.Release.Metadata.Config[key], args.Config[key], key)
		}
		require.Equal(t, req.Release.Metadata.CreatedAt, args.CreationDate)
		require.NotNil(t, args.Profiles)
		require.Empty(t, args.Profiles)
		require.Len(t, args.Devices, 2)
		require.Equal(t, "target-pool", args.Devices["root"]["pool"])
		require.Equal(t, "2", args.Devices["root"]["initial.lustre.owner_epoch"])
		require.Equal(t, "target-br", args.Devices["eth0"]["parent"])
		require.Equal(t, "00:16:3e:01:02:03", args.Devices["eth0"]["hwaddr"])
		require.NotContains(t, args.Config, "volatile.eth0.host_name")
		require.NotContains(t, args.Config, "volatile.last_state.power")
		require.Equal(t, "source-veth", req.Release.Metadata.Config["volatile.eth0.host_name"])
		require.Equal(t, "source-br", req.Release.Metadata.Devices["eth0"]["parent"])
		require.Len(t, args.Config[rootAdoptionMarker], 64)
		again, err := rootAdoptArgs(name, req)
		require.NoError(t, err)
		require.Equal(t, args.Config[rootAdoptionMarker], again.Config[rootAdoptionMarker])
		changed := util.CloneMap(args.Config)
		changed["volatile.apply_template"] = "unexpected"
		require.Error(t, rootAdoptConfigMatches(changed, args.Config))
		require.NoError(t, rootAdoptConfigMatches(args.Config, args.Config))
	}
}

func TestRootAdoptionRejectsUnknownDevicesAndMissingIdentity(t *testing.T) {
	for _, mutate := range []func(*api.XlabRootAdoptRequest){
		func(r *api.XlabRootAdoptRequest) { r.Release.Metadata.Config["volatile.cloud-init.instance-id"] = "" },
		func(r *api.XlabRootAdoptRequest) { r.Release.Metadata.Config["user.tc.id"] = "other" },
		func(r *api.XlabRootAdoptRequest) {
			r.Release.Metadata.Devices["gpu"] = map[string]string{"type": "gpu"}
		},
		func(r *api.XlabRootAdoptRequest) { r.Release.Metadata.Devices["fs-home"]["path"] = "/" },
		func(r *api.XlabRootAdoptRequest) { r.Release.Metadata.Devices["eth0"]["network"] = "source-network" },
		func(r *api.XlabRootAdoptRequest) {
			r.Target.Authority.InstanceID = "------------------------------------"
		},
	} {
		name, req := rootAdoptFixture()
		mutate(&req)
		_, err := rootAdoptArgs(name, req)
		require.Error(t, err)
	}
}

func TestRootAdoptionKeepsRequiredCapacityAtMetadataCreation(t *testing.T) {
	name, req := rootAdoptFixture()
	volume := "820cbe8f-9129-48a9-9d21-2930a72a65a3"
	req.Release.Metadata.Devices["data-capacity"] = map[string]string{"type": "disk", "path": "/data", "source": "/srv/source/" + volume + "/guest", "required": "true", "shift": "true"}
	_, err := rootAdoptArgs(name, req)
	require.Error(t, err)
	req.Capacity = &api.XlabCapacityDevice{VolumeID: volume, Source: "/srv/target/" + volume + "/guest"}
	args, err := rootAdoptArgs(name, req)
	require.NoError(t, err)
	require.Len(t, args.Devices, 3)
	require.Equal(t, req.Capacity.Source, args.Devices["data-capacity"]["source"])
	require.Equal(t, "true", args.Devices["data-capacity"]["required"])
	require.Equal(t, "true", args.Devices["data-capacity"]["shift"])
	require.Equal(t, "/srv/source/"+volume+"/guest", req.Release.Metadata.Devices["data-capacity"]["source"])
	require.NoError(t, rootAdoptCapacityMatches(args.Devices.CloneNative(), args.Devices.CloneNative()))
	changed := args.Devices.CloneNative()
	delete(changed, "data-capacity")
	require.Error(t, rootAdoptCapacityMatches(changed, args.Devices.CloneNative()))
	for _, mutate := range []func(){
		func() { req.Capacity.VolumeID = "other" },
		func() { req.Capacity.Source = "/srv/target/" + volume + "/mount" },
		func() { req.Release.Metadata.Devices["data-capacity"]["optional"] = "true" },
	} {
		old := *req.Capacity
		source := util.CloneMap(req.Release.Metadata.Devices["data-capacity"])
		mutate()
		_, err := rootAdoptArgs(name, req)
		require.Error(t, err)
		*req.Capacity = old
		req.Release.Metadata.Devices["data-capacity"] = source
	}
}
