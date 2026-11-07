//go:build integration

package api

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestProcessingReviewHTTPSIndependentDecisionAdoptionAndOriginalReceipt(t *testing.T) {
	service, manager, admin, server := browserAPI(t, 600*time.Second, custody.ExchangeSettings{})
	cookie, csrf := loginBrowser(t, server, manager, admin)
	prefix := "/v1/tenants/" + manager.Tenant + "/partners/" + manager.Partner
	worker, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"workflow_manage"})
	reviewer, reviewerAccount := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"inspect", "workflow_approve"})
	policy, err := checks.Normalize(checks.Policy{Schema: 2, Kind: "json_records", Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	control := &checks.Service{Custody: service}
	registered, err := control.Register(context.Background(), manager, "independent-api-output-policy", checks.PolicyRequest{Definition: policy})
	if err != nil {
		t.Fatal(err)
	}
	var output store.Configuration
	if json.Unmarshal(registered.Resource, &output) != nil {
		t.Fatal("output policy")
	}
	definition := workflow.Definition{Schema: 3, Name: "Definition-only independent approval", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", OutputPolicy: workflow.Reference{ID: output.ID, Version: output.Version, Hash: output.Hash}, Reason: "Approve mappings without receiving files", Definition: checks.RecordProjection{Schema: 1, Kind: "record_projection", Engine: "freightctl-record-projection-v1", SourcePolicyHash: strings.Repeat("a", 64), OutputKind: "json_records", Columns: []checks.ProjectionColumn{{Source: "account", Target: "account"}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2}}}
	call := func(token []byte, method, path, key string, body any, status int) []byte {
		t.Helper()
		var raw []byte
		if body != nil {
			raw = exchangeAPIJSON(t, body)
		}
		_, out := exchangeAPIRequest(t, server, method, prefix+path, nil, map[string]string{"Authorization": "Bearer " + string(token), "Idempotency-Key": key}, raw, status)
		return out
	}
	var drafted workflow.Result
	var cfg store.Configuration
	if json.Unmarshal(call(worker.Bytes, "POST", "/workflows/drafts", "independent-api-draft", workflow.DraftRequest{Definition: definition}, 200), &drafted) != nil || json.Unmarshal(drafted.Resource, &cfg) != nil {
		t.Fatal("draft")
	}
	var catalog workflow.ProcessingCatalog
	if json.Unmarshal(call(worker.Bytes, "GET", "/processing-workflows?limit=1", "", nil, 200), &catalog) != nil || len(catalog.Workflows) != 1 || catalog.Workflows[0].ID != cfg.ID || catalog.Workflows[0].ApprovalCurrent {
		t.Fatal("served catalog lost exact owned draft facts")
	}
	if json.Unmarshal(call(reviewer.Bytes, "GET", "/processing-workflows?limit=1", "", nil, 200), &catalog) != nil || len(catalog.Workflows) != 0 {
		t.Fatal("served catalog exposed another actor's workflow")
	}
	call(worker.Bytes, "POST", "/workflows/"+cfg.ID+"/1/approve", "no-self-approval", workflow.Decision{Hash: cfg.Hash, Revision: 1}, 403)
	request := workflow.ProcessingReviewRequest{Workflow: workflow.Reference{ID: cfg.ID, Version: cfg.Version, Hash: cfg.Hash}, Revision: 1, Reviewer: reviewerAccount.Actor, ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)}
	var proposed workflow.Result
	var review store.ProcessingReview
	if json.Unmarshal(call(worker.Bytes, "POST", "/processing-reviews", "independent-api-request", request, 200), &proposed) != nil || json.Unmarshal(proposed.Resource, &review) != nil {
		t.Fatal("proposal")
	}
	path := "/processing-reviews/" + review.ID
	call(reviewer.Bytes, "GET", "/workflows/"+cfg.ID+"/1", "", nil, 404)
	call(worker.Bytes, "POST", path+"/approve", "cannot-approve-own-review", workflow.Decision{Hash: review.Hash, Revision: 1}, 403)
	approvedWire := call(reviewer.Bytes, "POST", path+"/approve", "independent-api-approve", workflow.Decision{Hash: review.Hash, Revision: 1}, 200)
	var approved workflow.Result
	if json.Unmarshal(approvedWire, &approved) != nil || json.Unmarshal(approved.Resource, &review) != nil || review.State != "approved" {
		t.Fatal("reviewer approval")
	}
	call(worker.Bytes, "POST", path+"/adopt", "independent-api-adopt", workflow.Decision{Hash: review.Hash, Revision: 2}, 200)
	var observed store.ProcessingReview
	if json.Unmarshal(call(reviewer.Bytes, "GET", path, "", nil, 200), &observed) != nil || observed.State != "adopted" {
		t.Fatal("current adoption")
	}
	var replay workflow.Result
	if json.Unmarshal(call(reviewer.Bytes, "POST", path+"/approve", "independent-api-approve", workflow.Decision{Hash: review.Hash, Revision: 1}, 200), &replay) != nil || !replay.Replayed {
		t.Fatal("original approval receipt became current adoption")
	}
	var before, after any
	if json.Unmarshal(approved.Resource, &before) != nil || json.Unmarshal(replay.Resource, &after) != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("original approval receipt meaning changed")
	}
	call(reviewer.Bytes, "POST", path+"/withdraw", "independent-api-withdraw", workflow.Decision{Hash: review.Hash, Revision: 3}, 200)
	scope := store.Scope{Tenant: manager.Tenant, Partner: manager.Partner, TokenHash: secure.Digest(worker.Bytes)}
	tx, err := service.DB.Begin(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	err = tx.CheckProcessingReview(context.Background(), cfg.ID, 1, cfg.Hash)
	tx.Tx.Rollback(context.Background())
	if err == nil {
		t.Fatal("HTTP withdrawal lost permanent approval binding")
	}
}
