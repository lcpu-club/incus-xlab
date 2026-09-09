package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lxc/incus/v6/internal/server/auth"
	"github.com/lxc/incus/v6/internal/server/instance/operationlock"
	"github.com/lxc/incus/v6/internal/server/request"
	"github.com/lxc/incus/v6/internal/server/response"
	storagePools "github.com/lxc/incus/v6/internal/server/storage"
	"github.com/lxc/incus/v6/shared/api"
)

var instanceXlabRootForgetCmd = APIEndpoint{
	Name: "instanceXlabRootForget", Path: "instances/{name}/xlab-root-forget",
	Post: APIEndpointAction{Handler: instanceXlabRootForgetPost, AccessHandler: allowPermission(auth.ObjectTypeServer, auth.EntitlementCanEdit)},
}

func instanceXlabRootForgetPost(d *Daemon, r *http.Request) response.Response {
	if request.ProjectParam(r) != api.ProjectDefaultName {
		return response.BadRequest(errors.New("Root forget uses default project"))
	}
	name, err := url.PathUnescape(mux.Vars(r)["name"])
	if err != nil {
		return response.BadRequest(err)
	}
	var req api.XlabRootForgetRequest
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return response.BadRequest(err)
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return response.BadRequest(errors.New("Trailing forget content"))
	}
	id, err := uuid.Parse(req.Authority.InstanceID)
	if err != nil || id == uuid.Nil || id.String() != req.Authority.InstanceID || name != "tc-"+strings.ReplaceAll(id.String(), "-", "")[:12] {
		return response.BadRequest(errors.New("Forget instance name differs from authority"))
	}
	op, err := operationlock.Create(api.ProjectDefaultName, name, nil, operationlock.Action("xlab_root_forget"), false, false)
	if err != nil {
		return response.SmartError(err)
	}
	defer op.Done(nil)
	pool, err := storagePools.LoadByName(d.State(), req.Pool)
	if err != nil {
		return response.SmartError(err)
	}
	result, err := storagePools.ForgetRootMetadata(pool, req)
	if err != nil {
		return response.SmartError(err)
	}
	return response.SyncResponse(true, result)
}
