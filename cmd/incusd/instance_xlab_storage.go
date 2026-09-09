package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	"github.com/lxc/incus/v6/internal/server/auth"
	"github.com/lxc/incus/v6/internal/server/instance"
	"github.com/lxc/incus/v6/internal/server/instance/operationlock"
	"github.com/lxc/incus/v6/internal/server/request"
	"github.com/lxc/incus/v6/internal/server/response"
	storagePools "github.com/lxc/incus/v6/internal/server/storage"
	"github.com/lxc/incus/v6/shared/api"
)

var instanceXlabRootReleaseCmd = APIEndpoint{
	Name: "instanceXlabRootRelease",
	Path: "instances/{name}/xlab-root-release",
	// Platform storage orchestration is a server administration operation, not
	// permission to manage any student's ordinary instance state.
	Post: APIEndpointAction{Handler: instanceXlabRootReleasePost, AccessHandler: allowPermission(auth.ObjectTypeServer, auth.EntitlementCanEdit)},
}

func instanceXlabRootReleasePost(d *Daemon, r *http.Request) response.Response {
	if request.ProjectParam(r) != "default" {
		return response.BadRequest(errors.New("Xlab root release uses the default project"))
	}
	name, err := url.PathUnescape(mux.Vars(r)["name"])
	if err != nil {
		return response.SmartError(err)
	}
	var req api.XlabRootReleaseRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4097))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return response.BadRequest(err)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return response.BadRequest(errors.New("Trailing release request content"))
	}
	// Deliberately local: independent Incus instances do not forward release calls.
	inst, err := instance.LoadByProjectAndName(d.State(), "default", name)
	if err != nil {
		return response.SmartError(err)
	}
	driver, ok := inst.(interface {
		XlabReleaseRoot(api.XlabRootReleaseRequest) (*api.XlabRootRelease, error)
	})
	if !ok {
		return response.BadRequest(errors.New("Instance driver does not support Xlab root release"))
	}
	result, err := driver.XlabReleaseRoot(req)
	if err != nil {
		return response.SmartError(err)
	}
	return response.SyncResponse(true, result)
}

var instanceXlabRootInspectionCmd = APIEndpoint{
	Name: "instanceXlabRootInspection",
	Path: "instances/{name}/xlab-root-inspect",
	Post: APIEndpointAction{Handler: instanceXlabRootInspectionPost, AccessHandler: allowPermission(auth.ObjectTypeServer, auth.EntitlementCanEdit)},
}

func instanceXlabRootInspectionPost(d *Daemon, r *http.Request) response.Response {
	if request.ProjectParam(r) != "default" {
		return response.BadRequest(errors.New("Xlab root inspection uses the default project"))
	}
	name, err := url.PathUnescape(mux.Vars(r)["name"])
	if err != nil {
		return response.SmartError(err)
	}
	var req api.XlabRootInspectionRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 8193))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return response.BadRequest(err)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return response.BadRequest(errors.New("Trailing root inspection content"))
	}
	op, err := operationlock.Create(api.ProjectDefaultName, name, nil, operationlock.Action("xlab_root_inspect"), false, false)
	if err != nil {
		return response.SmartError(err)
	}
	defer op.Done(nil)
	inst, err := instance.LoadByProjectAndName(d.State(), "default", name)
	if err != nil {
		return response.SmartError(err)
	}
	pool, err := storagePools.LoadByInstance(d.State(), inst)
	if err != nil {
		return response.SmartError(err)
	}
	result, err := storagePools.InspectInstanceRoot(pool, inst, req)
	if err != nil {
		return response.SmartError(err)
	}
	return response.SyncResponse(true, result)
}
