package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) checks(w http.ResponseWriter, r *http.Request) {
	scope, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	key := r.Header.Get("Idempotency-Key")
	var result any
	switch r.Pattern {
	case "GET /v1/tenants/{tenant}/partners/{partner}/checks/{file}/processing-contracts":
		var selected *store.OnboardingReference
		selected, err = processingOutputReference(r.URL.RawQuery)
		if err == nil {
			if selected == nil {
				result, err = s.Checks.DescribeProcessing(r.Context(), scope, r.PathValue("file"))
			} else {
				result, err = s.Checks.DescribeProcessingOutput(r.Context(), scope, r.PathValue("file"), *selected)
			}
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/scanners/{scanner}/{version}", "POST /v1/tenants/{tenant}/partners/{partner}/scanners/{scanner}/{version}/revoke":
		version, parseErr := strconv.Atoi(r.PathValue("version"))
		if parseErr != nil || version < 1 {
			err = checks.ErrInput
			break
		}
		if r.Method == http.MethodGet {
			result, err = s.Checks.Scanner(r.Context(), scope, r.PathValue("scanner"), version)
		} else {
			var decision workflow.Decision
			if err = workflowInput(w, r, &decision); err == nil {
				result, err = s.Checks.RevokeScanner(r.Context(), scope, r.PathValue("scanner"), version, key, decision)
			}
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/pgp-keys":
		var request checks.PGPKeyRequest
		if err = workflowInput(w, r, &request); err == nil {
			defer secure.Clear(request.PublicKey)
			result, err = s.Checks.RegisterPGPKey(r.Context(), scope, key, request)
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/pgp-keys/{key}/{version}", "POST /v1/tenants/{tenant}/partners/{partner}/pgp-keys/{key}/{version}/revoke":
		version, parseErr := strconv.Atoi(r.PathValue("version"))
		if parseErr != nil || version < 1 {
			err = checks.ErrInput
			break
		}
		if r.Method == http.MethodGet {
			result, err = s.Checks.PGPKey(r.Context(), scope, r.PathValue("key"), version)
		} else {
			var decision workflow.Decision
			if err = workflowInput(w, r, &decision); err == nil {
				result, err = s.Checks.RevokePGPKey(r.Context(), scope, r.PathValue("key"), version, key, decision)
			}
		}
	case "PUT /v1/tenants/{tenant}/partners/{partner}/checks/{file}/signature":
		revision, parseErr := strconv.ParseInt(r.Header.Get("If-Check-Revision"), 10, 64)
		if parseErr != nil || revision < 1 {
			err = checks.ErrInput
			break
		}
		r.Body = http.MaxBytesReader(w, r.Body, secure.MaxPGPWire)
		wire, readErr := io.ReadAll(r.Body)
		defer secure.Clear(wire)
		if readErr != nil {
			err = checks.ErrInput
		} else {
			result, err = s.Checks.AttachSignature(r.Context(), scope, r.PathValue("file"), key, r.Header.Get("X-Data-SHA256"), r.Header.Get("X-Policy-Hash"), revision, wire)
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/checks/{file}/signature":
		artifact, data, readErr := s.Checks.SignatureContent(r.Context(), scope, r.PathValue("file"))
		if readErr != nil {
			err = readErr
			break
		}
		defer data.Close()
		w.Header().Set("Content-Type", "application/pgp-signature")
		w.Header().Set("X-Content-SHA256", artifact.SHA256)
		w.Header().Set("Content-Length", strconv.FormatInt(artifact.Size, 10))
		_, _ = io.CopyN(w, data, artifact.Size)
		return
	case "GET /v1/tenants/{tenant}/partners/{partner}/checks":
		limit := 50
		if value := r.URL.Query().Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
			if err != nil {
				err = checks.ErrInput
				break
			}
		}
		result, err = s.Checks.List(r.Context(), scope, r.URL.Query().Get("after"), limit)
	case "GET /v1/tenants/{tenant}/partners/{partner}/intake-policy":
		result, err = s.Checks.Policy(r.Context(), scope)
	case "POST /v1/tenants/{tenant}/partners/{partner}/intake-policy":
		var request checks.PolicyRequest
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.Checks.Register(r.Context(), scope, key, request)
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/intake-policy/revoke":
		var request checks.PolicyDecision
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.Checks.Revoke(r.Context(), scope, key, request)
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/checks/{file}/projection-preview":
		var request checks.ProjectionOptions
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.Checks.PreviewProjection(r.Context(), scope, r.PathValue("file"), request)
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/checks/{file}/projections":
		var request struct {
			Plan checks.ProjectionPlan `json:"plan"`
		}
		if err = workflowInput(w, r, &request); err == nil {
			if request.Plan.Context.Source.File.ID != r.PathValue("file") {
				err = checks.ErrInput
			} else {
				result, err = s.Checks.ProposeProjection(r.Context(), scope, key, request.Plan)
			}
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/projections/{projection}":
		result, err = s.Checks.GetProjection(r.Context(), scope, r.PathValue("projection"))
	case "POST /v1/tenants/{tenant}/partners/{partner}/projections/{projection}/decide":
		var request checks.PolicyRecheckDecision
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.Checks.DecideProjection(r.Context(), scope, r.PathValue("projection"), key, request)
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/projections/{projection}/start":
		var request checks.ProjectionStartDecision
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.Checks.StartProjection(r.Context(), scope, r.PathValue("projection"), key, request)
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/projections/{projection}/work":
		var request checks.ProjectionAttempt
		if err = workflowInput(w, r, &request); err == nil {
			if request.ID != r.PathValue("projection") {
				err = checks.ErrInput
			} else {
				result, err = s.Checks.WorkProjection(r.Context(), scope, key, request)
			}
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/checks/{file}/recheck-preview":
		var request checks.RecheckOptions
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.Checks.PreviewRecheck(r.Context(), scope, r.PathValue("file"), request)
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/checks/{file}/rechecks":
		var request struct {
			Plan checks.RecheckPlan `json:"plan"`
		}
		if err = workflowInput(w, r, &request); err == nil {
			if request.Plan.Source.File.ID != r.PathValue("file") {
				err = checks.ErrInput
			} else {
				result, err = s.Checks.ProposeRecheck(r.Context(), scope, key, request.Plan)
			}
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/checks/{file}/rechecks":
		limit := 50
		if value := r.URL.Query().Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
		}
		if err == nil {
			result, err = s.Checks.ListRechecks(r.Context(), scope, r.PathValue("file"), r.URL.Query().Get("after"), limit)
		} else {
			err = checks.ErrInput
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/rechecks/{recheck}":
		result, err = s.Checks.GetRecheck(r.Context(), scope, r.PathValue("recheck"))
	case "POST /v1/tenants/{tenant}/partners/{partner}/rechecks/{recheck}/decide":
		var request checks.PolicyRecheckDecision
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.Checks.DecideRecheck(r.Context(), scope, r.PathValue("recheck"), key, request)
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/rechecks/{recheck}/copy":
		r.Body = http.MaxBytesReader(w, r.Body, 1)
		var data []byte
		data, err = io.ReadAll(r.Body)
		if err != nil || len(data) != 0 {
			err = checks.ErrInput
		} else {
			result, err = s.Checks.CopyRecheck(r.Context(), scope, r.PathValue("recheck"), key)
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/checks/{file}":
		result, err = s.Checks.Get(r.Context(), scope, r.PathValue("file"))
	case "POST /v1/tenants/{tenant}/partners/{partner}/checks/{file}/recover":
		var decision checks.RecoveryDecision
		if err = workflowInput(w, r, &decision); err == nil {
			result, err = s.Checks.Recover(r.Context(), scope, r.PathValue("file"), key, decision)
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/checks/{file}/run":
		r.Body = http.MaxBytesReader(w, r.Body, 1)
		data, readErr := io.ReadAll(r.Body)
		if readErr != nil || len(data) != 0 {
			err = checks.ErrInput
		} else {
			result, err = s.Checks.Run(r.Context(), scope, r.PathValue("file"), key)
		}
	default:
		var request checks.ReleaseDecision
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.Checks.Release(r.Context(), scope, r.PathValue("file"), key, request)
		}
	}
	if errors.Is(err, checks.ErrInput) || errors.Is(err, workflow.ErrInput) {
		fail(w, 400, "invalid_check_request")
	} else if err != nil {
		failure(w, err)
	} else {
		respond(w, 200, result)
	}
}
