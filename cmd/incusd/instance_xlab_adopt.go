package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lxc/incus/v6/internal/server/auth"
	"github.com/lxc/incus/v6/internal/server/db"
	deviceConfig "github.com/lxc/incus/v6/internal/server/device/config"
	"github.com/lxc/incus/v6/internal/server/instance"
	"github.com/lxc/incus/v6/internal/server/instance/instancetype"
	"github.com/lxc/incus/v6/internal/server/instance/operationlock"
	"github.com/lxc/incus/v6/internal/server/request"
	"github.com/lxc/incus/v6/internal/server/response"
	storagePools "github.com/lxc/incus/v6/internal/server/storage"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/osarch"
	"github.com/lxc/incus/v6/shared/revert"
	"github.com/lxc/incus/v6/shared/util"
)

var instanceXlabRootAdoptCmd = APIEndpoint{
	Name: "instanceXlabRootAdopt", Path: "instances/{name}/xlab-root-adopt",
	Post: APIEndpointAction{Handler: instanceXlabRootAdoptPost, AccessHandler: allowPermission(auth.ObjectTypeServer, auth.EntitlementCanEdit)},
}

const rootAdoptionMarker = "user.xlab.root_adoption"

func rootAdoptConfigMatches(actual, want map[string]string) error {
	for key, value := range want {
		if actual[key] != value {
			return errors.New("Adopted instance config differs from stopped source metadata")
		}
	}
	// Absence is meaningful: a consumed create/copy trigger must stay consumed.
	if actual["volatile.apply_template"] != want["volatile.apply_template"] {
		return errors.New("Adoption changed pending template state")
	}
	return nil
}

// Build local metadata from the retained stopped source. Host devices are rebuilt
// on the target; immutable guest identity and pending template state are preserved.
func rootAdoptArgs(name string, req api.XlabRootAdoptRequest) (db.InstanceArgs, error) {
	var out db.InstanceArgs
	a := req.Target.Authority
	m := req.Release.Metadata
	id, err := uuid.Parse(a.InstanceID)
	if err != nil || id == uuid.Nil || id.String() != a.InstanceID || name != "tc-"+strings.ReplaceAll(a.InstanceID, "-", "")[:12] || req.Bridge == "" || strings.ContainsAny(req.Bridge, "/\x00\n ") || m == nil {
		return out, errors.New("Adoption requires canonical instance identity and a target bridge")
	}
	if err := m.Validate(); err != nil {
		return out, err
	}
	if m.Config["user.tc.id"] != a.InstanceID || m.Config["user.tc.managed"] != "true" {
		return out, errors.New("Source metadata belongs to another managed instance")
	}
	config := util.CloneMap(m.Config)
	// Device-local volatile fields describe source-host interfaces, not guest ID.
	for key := range config {
		for dev := range m.Devices {
			if strings.HasPrefix(key, "volatile."+dev+".") {
				delete(config, key)
			}
		}
	}
	delete(config, "volatile.idmap.current")
	for key := range config {
		if strings.HasPrefix(key, "volatile.last_state.") && key != "volatile.last_state.idmap" {
			delete(config, key)
		}
	}
	root := util.CloneMap(m.Devices["root"])
	nic := util.CloneMap(m.Devices["eth0"])
	if root["type"] != "disk" || root["path"] != "/" || root["source"] != "" || nic["type"] != "nic" || nic["nictype"] != "bridged" || nic["network"] != "" {
		return out, errors.New("Source root/NIC topology cannot be adopted")
	}
	capacity, err := rootAdoptCapacityDevice(req)
	if err != nil {
		return out, err
	}
	for name, dev := range m.Devices {
		if name == "root" || name == "eth0" {
			continue
		}
		managed := strings.HasPrefix(name, "fs-") || name == "home" || name == "tools" || name == "cache" || strings.HasPrefix(name, "data-")
		if !managed || dev["type"] != "disk" || dev["path"] == "/" {
			return out, errors.New("Source has devices without a target attachment plan")
		}
	}
	for key := range root {
		if strings.HasPrefix(key, "initial.") {
			delete(root, key)
		}
	}
	root["pool"], root["size"] = req.Target.Pool, strconv.FormatInt(a.QuotaBytes, 10)
	root["initial.lustre.volume_id"] = a.VolumeID
	root["initial.lustre.owner_epoch"] = strconv.FormatUint(a.Epoch, 10)
	root["initial.lustre.generation"] = strconv.FormatUint(a.Generation, 10)
	nic["parent"] = req.Bridge
	if nic["hwaddr"] == "" {
		nic["hwaddr"] = m.Config["volatile.eth0.hwaddr"]
	}
	if nic["hwaddr"] == "" {
		return out, errors.New("Source metadata lacks persistent NIC address")
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	digest := sha256.Sum256(raw)
	config[rootAdoptionMarker] = hex.EncodeToString(digest[:])
	arch, err := osarch.ArchitectureID(m.Architecture)
	if err != nil {
		return out, err
	}
	devices := map[string]map[string]string{"root": root, "eth0": nic}
	if capacity != nil {
		devices["data-capacity"] = capacity
	}
	return db.InstanceArgs{Project: api.ProjectDefaultName, Name: name, Type: instancetype.Container, Architecture: arch, CreationDate: m.CreatedAt, LastUsedDate: m.LastUsedAt, Description: m.Description, Config: config, Devices: deviceConfig.NewDevices(devices), Profiles: []api.Profile{}}, nil
}

func instanceXlabRootAdoptPost(d *Daemon, r *http.Request) response.Response {
	if request.ProjectParam(r) != api.ProjectDefaultName {
		return response.BadRequest(errors.New("Root adoption uses default project"))
	}
	name, err := url.PathUnescape(mux.Vars(r)["name"])
	if err != nil {
		return response.BadRequest(err)
	}
	var req api.XlabRootAdoptRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return response.BadRequest(err)
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return response.BadRequest(errors.New("Trailing adoption content"))
	}
	args, err := rootAdoptArgs(name, req)
	if err != nil {
		return response.BadRequest(err)
	}
	pool, err := storagePools.LoadByName(d.State(), req.Target.Pool)
	if err != nil {
		return response.SmartError(err)
	}
	unlock, err := storagePools.LockRootAdoption(pool, req)
	if err != nil {
		return response.SmartError(err)
	}
	defer unlock()
	existing, err := instance.LoadByProjectAndName(d.State(), api.ProjectDefaultName, name)
	if err == nil {
		op, err := operationlock.Create(api.ProjectDefaultName, name, nil, operationlock.Action("xlab_root_adopt_retry"), false, false)
		if err != nil {
			return response.SmartError(err)
		}
		defer op.Done(nil)
		// An earlier creator might have rolled back between lookup and locking.
		existing, err = instance.LoadByProjectAndName(d.State(), api.ProjectDefaultName, name)
		if err != nil {
			return response.SmartError(err)
		}
		if existing.LocalConfig()[rootAdoptionMarker] != args.Config[rootAdoptionMarker] {
			return response.BadRequest(errors.New("Existing instance is not this metadata adoption"))
		}
		if err := rootAdoptConfigMatches(existing.LocalConfig(), args.Config); err != nil {
			return response.SmartError(err)
		}
		if err := rootAdoptCapacityMatches(existing.LocalDevices().CloneNative(), args.Devices.CloneNative()); err != nil {
			return response.BadRequest(err)
		}
		result, err := storagePools.InspectInstanceRoot(pool, existing, req.Target)
		if err != nil {
			return response.SmartError(err)
		}
		return response.SyncResponse(true, result)
	}
	if !response.IsNotFoundError(err) {
		return response.SmartError(err)
	}
	reverter := revert.New()
	// CreateInternal modifies its config map in place. Keep the retained expected
	// metadata separate so its generation reset cannot rewrite our comparison.
	createArgs := args
	createArgs.Config = util.CloneMap(args.Config)
	createArgs.Devices = args.Devices.Clone()
	inst, op, cleanup, err := instance.CreateInternal(d.State(), createArgs, nil, false, true, false)
	if err != nil {
		return response.SmartError(err)
	}
	defer op.Done(nil)
	// Roll back local records before making them observable as a completed
	// operation. A concurrent inspect/adopt retry must not acknowledge a record
	// that this handler is about to remove.
	defer reverter.Fail()
	reverter.Add(cleanup)
	// CreateInternal regenerates this value for ordinary create/recovery. This
	// operation must preserve the stopped guest's original UUID generation instead.
	if err := inst.VolatileSet(map[string]string{"volatile.uuid.generation": req.Release.Metadata.Config["volatile.uuid.generation"]}); err != nil {
		return response.SmartError(err)
	}
	if err := rootAdoptConfigMatches(inst.LocalConfig(), args.Config); err != nil {
		return response.SmartError(err)
	}
	if err := rootAdoptCapacityMatches(inst.LocalDevices().CloneNative(), args.Devices.CloneNative()); err != nil {
		return response.BadRequest(err)
	}
	cleanup, err = storagePools.AdoptInstanceRoot(pool, inst, req)
	if err != nil {
		return response.SmartError(err)
	}
	reverter.Add(cleanup)
	result, err := storagePools.InspectInstanceRoot(pool, inst, req.Target)
	if err != nil {
		return response.SmartError(err)
	}
	reverter.Success()
	return response.SyncResponse(true, result)
}

func rootAdoptCapacityDevice(req api.XlabRootAdoptRequest) (map[string]string, error) {
	source, present := req.Release.Metadata.Devices["data-capacity"]
	if !present && req.Capacity == nil {
		return nil, nil
	}
	if !present || req.Capacity == nil {
		return nil, errors.New("Capacity adoption requires both source device and target plan")
	}
	id, err := uuid.Parse(req.Capacity.VolumeID)
	if err != nil || id == uuid.Nil || id.String() != req.Capacity.VolumeID || req.Capacity.VolumeID == req.Target.Authority.VolumeID {
		return nil, errors.New("Invalid capacity volume identity")
	}
	validPath := func(p string) bool {
		return filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\n\r") && filepath.Base(p) == "guest" && filepath.Base(filepath.Dir(p)) == id.String()
	}
	if len(source) != 5 || source["type"] != "disk" || source["path"] != "/data" || source["required"] != "true" || source["shift"] != "true" || !validPath(source["source"]) || !validPath(req.Capacity.Source) {
		return nil, errors.New("Capacity adoption requires the exact required idmapped export")
	}
	return map[string]string{"type": "disk", "path": "/data", "source": req.Capacity.Source, "required": "true", "shift": "true"}, nil
}

func rootAdoptCapacityMatches(actual, want map[string]map[string]string) error {
	if !reflect.DeepEqual(actual["data-capacity"], want["data-capacity"]) {
		return errors.New("Adopted capacity device differs from the required target plan")
	}
	return nil
}
