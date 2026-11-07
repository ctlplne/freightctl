//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/calendar"
	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestProcessingWorkflowHTTPSOrdinaryApprovalRunAndHeldOutput(t *testing.T) {
	processingWorkflowHTTPS(t, false)
}

func TestProducerProjectionHTTPSApprovalRunAndHeldOutputKeepDefaultIngress(t *testing.T) {
	processingWorkflowHTTPS(t, true)
}

func TestComposedProducerProjectionHTTPSRequiresFreshChecksAndNewApprovalWithoutRelease(t *testing.T) {
	processingWorkflowHTTPSProfile(t, true, true)
}

func TestProcessingScheduleHTTPSNoDeliveryGrantQueuesOrdinaryHeldTaskWithExactReplay(t *testing.T) {
	processingWorkflowHTTPSScenario(t, true, false, true)
}

func processingWorkflowHTTPS(t *testing.T, producerBound bool) {
	processingWorkflowHTTPSProfile(t, producerBound, false)
}

func processingWorkflowHTTPSProfile(t *testing.T, producerBound, composed bool) {
	processingWorkflowHTTPSScenario(t, producerBound, composed, false)
}

func processingWorkflowHTTPSScenario(t *testing.T, producerBound, composed, scheduled bool) {
	service, manager, admin, server := browserAPI(t, 600*time.Second, custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16})
	cookie, csrf := loginBrowser(t, server, manager, admin)
	prefix := "/v1/tenants/" + manager.Tenant + "/partners/" + manager.Partner
	permissions := []string{"read", "write", "check_run", "workflow_manage", "workflow_approve", "workflow_execute"}
	if scheduled {
		permissions = append(permissions, "list", "check_release")
	}
	token, participant := exchangeAPIParticipant(t, server, prefix, cookie, csrf, permissions)
	actor := store.Scope{Tenant: manager.Tenant, Partner: manager.Partner, TokenHash: secure.Digest(token.Bytes)}
	ctx := context.Background()
	control := &checks.Service{Custody: service}
	policy, err := checks.Normalize(checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	input, err := control.Register(ctx, manager, "wf-input-policy", checks.PolicyRequest{Definition: policy})
	if err != nil {
		t.Fatal(err)
	}
	var inputPolicy store.Configuration
	if json.Unmarshal(input.Resource, &inputPolicy) != nil {
		t.Fatal("input policy")
	}
	body := "account\n0001\n"
	var source *store.File
	if scheduled {
		mode := uint32(0777)
		if _, err = service.PathCommand(ctx, manager, "served-calendar-folder", store.PathCommand{Operation: "mkdir", Path: "/incoming", Mode: &mode}); err != nil {
			t.Fatal(err)
		}
		source, _, err = service.AcceptAt(ctx, actor, "wf-input", int64(len(body)), secure.Digest([]byte(body)), strings.NewReader(body), custody.UploadTarget{Path: "/incoming/settlement.csv"})
	} else {
		source, _, err = service.Accept(ctx, actor, "wf-input", int64(len(body)), secure.Digest([]byte(body)), strings.NewReader(body))
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = control.Run(ctx, actor, source.ID, "wf-check-input"); err != nil {
		t.Fatal(err)
	}
	if scheduled {
		tx, err := service.DB.Begin(ctx, actor)
		if err != nil {
			t.Fatal(err)
		}
		check, err := tx.FileCheck(ctx, source.ID, false)
		tx.Tx.Rollback(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = control.Release(ctx, actor, source.ID, "served-calendar-source-release", checks.ReleaseDecision{SHA256: source.SHA256, PolicyHash: check.PolicyHash, ReportHash: check.ReportHash, Revision: check.Revision}); err != nil {
			t.Fatal(err)
		}
	}
	output := policy
	output.Schema = 2
	output.Kind = "json_records"
	var outputPolicy store.Configuration
	if producerBound {
		registered, err := control.RegisterOutputPolicy(ctx, manager, "wf-producer-output-policy", checks.OutputPolicyRequest{Producer: participant.Actor, Definition: output})
		if err != nil {
			t.Fatal(err)
		}
		var contract checks.OutputPolicyRecord
		if json.Unmarshal(registered.Resource, &contract) != nil || contract.Policy == nil {
			t.Fatal("producer output policy")
		}
		outputPolicy = *contract.Policy
		query := "?output_policy_id=" + outputPolicy.ID + "&output_policy_version=1&output_policy_hash=" + outputPolicy.Hash
		_, raw := exchangeAPIRequest(t, server, "GET", prefix+"/checks/"+source.ID+"/processing-contracts"+query, nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes)}, nil, 200)
		var described checks.ProcessingContracts
		if json.Unmarshal(raw, &described) != nil || described.Profile != "record-processing-contracts-v2" || described.OutputBinding == nil || described.OutputBinding.Producer.Actor != participant.Actor || described.Source.ID != source.ID || described.OutputPolicy.Reference.ID != outputPolicy.ID {
			t.Fatal("served metadata selection did not bind this producer/source/output")
		}
	} else {
		registered, err := control.Register(ctx, manager, "wf-output-policy", checks.PolicyRequest{ExpectedVersion: 1, Definition: output})
		if err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal(registered.Resource, &outputPolicy) != nil {
			t.Fatal("output policy")
		}
	}
	rules, err := checks.NormalizeRecordProjection(policy, checks.RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: inputPolicy.Hash, OutputKind: "json_records", Columns: []checks.ProjectionColumn{{Source: "account", Target: "account"}}})
	if err != nil {
		t.Fatal(err)
	}
	definition := workflow.Definition{Schema: 3, Name: "Ordinary approved processing", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: outputPolicy.ID, Version: outputPolicy.Version, Hash: outputPolicy.Hash}, Reason: "Create a separately held immutable output"}}
	call := func(path, key string, body any) []byte {
		t.Helper()
		headers := map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": key}
		var raw []byte
		if body != nil {
			raw = exchangeAPIJSON(t, body)
		}
		_, response := exchangeAPIRequest(t, server, "POST", prefix+path, nil, headers, raw, 200)
		return response
	}
	var draft workflow.Result
	if json.Unmarshal(call("/workflows/drafts", "wf-draft", workflow.DraftRequest{Definition: definition}), &draft) != nil {
		t.Fatal("draft envelope")
	}
	var cfg store.Configuration
	if json.Unmarshal(draft.Resource, &cfg) != nil {
		t.Fatal("draft configuration")
	}
	request := workflow.RunRequest{Workflow: workflow.Reference{ID: cfg.ID, Version: cfg.Version, Hash: cfg.Hash}, FileID: source.ID}
	_, _ = exchangeAPIRequest(t, server, "POST", prefix+"/workflow-runs", nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": "wf-unapproved"}, exchangeAPIJSON(t, request), 409)
	call("/workflows/"+cfg.ID+"/1/approve", "wf-approve", workflow.Decision{Hash: cfg.Hash, Revision: cfg.Revision})
	var created workflow.Result
	var run store.WorkflowRun
	if scheduled {
		due := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
		x := workflow.ScheduleSelection{Name: "HTTPS owned processing calendar", Workflow: request.Workflow, Source: workflow.ScheduleSourceSelection{Kind: workflow.ProcessingScheduleSource, Directory: "/incoming", Pattern: "*.csv"}, Calendar: calendar.Selection{Zone: "UTC", Start: due, End: due.Add(time.Minute), Times: []string{due.Format("15:04:05")}, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Holidays: []string{}, Gap: "skip", Fold: "both"}, Missed: "all", CatchUp: 1, MaxActive: 1, MaxFiles: 1, Deadline: 30, Grace: 1, ExpectedAuthority: participant.AuthorityRevision}
		var preview workflow.SchedulePreview
		if json.Unmarshal(call("/workflow-schedules/preview", "served-calendar-preview", x), &preview) != nil || preview.Definition.Processing == nil || len(preview.Effects) != 0 {
			t.Fatal("served calendar preview")
		}
		var drafted workflow.Result
		if json.Unmarshal(call("/workflow-schedules/drafts", "served-calendar-draft", workflow.ScheduleDraftRequest{Selection: x, Hash: preview.Hash}), &drafted) != nil {
			t.Fatal("served calendar draft envelope")
		}
		var record workflow.ScheduleResource
		if json.Unmarshal(drafted.Resource, &record) != nil || record.Profile != "owned-record-processing-schedule-v1" {
			t.Fatal("served calendar draft")
		}
		path := "/workflow-schedules/" + record.Schedule.ID + "/1"
		call(path+"/activate", "served-calendar-activate", workflow.Decision{Hash: record.Schedule.Hash, Revision: record.Schedule.Revision})
		timer := time.NewTimer(time.Until(due.Add(30 * time.Millisecond)))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
		first := call(path+"/tick", "served-calendar-tick", workflow.ScheduleTickRequest{Limit: 1})
		var tick workflow.Result
		if json.Unmarshal(first, &tick) != nil {
			t.Fatal("served tick envelope")
		}
		var value workflow.ScheduleTickResult
		if json.Unmarshal(tick.Resource, &value) != nil || len(value.RunIDs) != 1 || value.ExternalContact {
			t.Fatal("served processing claim")
		}
		var replay workflow.Result
		if json.Unmarshal(call(path+"/tick", "served-calendar-tick", workflow.ScheduleTickRequest{Limit: 1}), &replay) != nil || !bytes.Equal(tick.Resource, replay.Resource) {
			t.Fatal("served tick replay changed claim")
		}
		view, err := (&workflow.Service{Custody: service, Processor: control}).Status(ctx, actor, value.RunIDs[0])
		if err != nil {
			t.Fatal(err)
		}
		run = *view.Run
	} else if json.Unmarshal(call("/workflow-runs", "wf-run", request), &created) != nil {
		t.Fatal("run envelope")
	}
	if !scheduled && json.Unmarshal(created.Resource, &run) != nil {
		t.Fatal("run receipt")
	}
	var result workflow.WorkResult
	if json.Unmarshal(call("/workflow-runs/"+run.ID+"/work", "wf-work", nil), &result) != nil || result.Processing == nil || result.Processing.State != "completed" || result.Status.ObservedReason != "output_held" || len(result.Status.Steps) != 0 {
		t.Fatal("served workflow did not use held-output processing")
	}
	if _, _, err = service.Download(ctx, actor, result.Processing.FileID); !errors.Is(err, store.ErrState) {
		t.Fatal("ordinary work request granted release", err)
	}
	var replay workflow.WorkResult
	if json.Unmarshal(call("/workflow-runs/"+run.ID+"/work", "wf-work", nil), &replay) != nil || !replay.Replayed || replay.Processing.ID != result.Processing.ID || replay.Processing.Attempts != 1 {
		t.Fatal("public replay selected a new attempt")
	}
	if composed {
		if _, err = control.Run(ctx, actor, result.Processing.FileID, "composed-source-check"); err != nil {
			t.Fatal(err)
		}
		registered, err := control.RegisterOutputPolicy(ctx, manager, "composed-output-policy", checks.OutputPolicyRequest{Producer: participant.Actor, Definition: policy})
		if err != nil {
			t.Fatal(err)
		}
		var contract checks.OutputPolicyRecord
		if json.Unmarshal(registered.Resource, &contract) != nil || contract.Policy == nil {
			t.Fatal("composed output contract")
		}
		ref := contract.Policy
		query := "?output_policy_id=" + ref.ID + "&output_policy_version=1&output_policy_hash=" + ref.Hash
		_, raw := exchangeAPIRequest(t, server, "GET", prefix+"/checks/"+result.Processing.FileID+"/processing-contracts"+query, nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes)}, nil, 200)
		var described checks.ProcessingContracts
		if json.Unmarshal(raw, &described) != nil || described.Profile != "record-processing-contracts-v3" || described.SourceOrigin == nil || described.SourceOrigin.ProjectionID != result.Processing.ID {
			t.Fatal("served composed lineage metadata")
		}
		rules, err := checks.NormalizeRecordProjection(output, checks.RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: outputPolicy.Hash, OutputKind: "csv", Columns: []checks.ProjectionColumn{{Source: "account", Target: "account"}}})
		if err != nil {
			t.Fatal(err)
		}
		definition := workflow.Definition{Schema: 3, Name: "Second separately approved task", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: ref.ID, Version: ref.Version, Hash: ref.Hash}, Reason: "Consume one exact checked owned producer output"}}
		var second workflow.Result
		if json.Unmarshal(call("/workflows/drafts", "composed-draft", workflow.DraftRequest{Definition: definition}), &second) != nil {
			t.Fatal("second draft envelope")
		}
		var cfg store.Configuration
		if json.Unmarshal(second.Resource, &cfg) != nil {
			t.Fatal("second draft")
		}
		request := workflow.RunRequest{Workflow: workflow.Reference{ID: cfg.ID, Version: cfg.Version, Hash: cfg.Hash}, FileID: result.Processing.FileID}
		_, _ = exchangeAPIRequest(t, server, "POST", prefix+"/workflow-runs", nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": "composed-unapproved"}, exchangeAPIJSON(t, request), 409)
		call("/workflows/"+cfg.ID+"/1/approve", "composed-approve", workflow.Decision{Hash: cfg.Hash, Revision: cfg.Revision})
		var created workflow.Result
		if json.Unmarshal(call("/workflow-runs", "composed-run", request), &created) != nil {
			t.Fatal("second run envelope")
		}
		var secondRun store.WorkflowRun
		if json.Unmarshal(created.Resource, &secondRun) != nil {
			t.Fatal("second run")
		}
		var worked workflow.WorkResult
		if json.Unmarshal(call("/workflow-runs/"+secondRun.ID+"/work", "composed-work", nil), &worked) != nil || worked.Processing == nil || worked.Processing.State != "completed" || worked.Status.Processing.Released || worked.Processing.FileID == result.Processing.FileID {
			t.Fatal("served composed task did not produce separately held bytes")
		}
		var d checks.ProjectionDefinition
		if json.Unmarshal(worked.Processing.Definition, &d) != nil || d.Schema != 4 || d.Plan.SourceOrigin == nil || *d.Plan.SourceOrigin != *described.SourceOrigin {
			t.Fatal("served source lineage changed")
		}
		if _, _, err := service.Download(ctx, actor, worked.Processing.FileID); !errors.Is(err, store.ErrState) {
			t.Fatal("composition granted release", err)
		}
	}
	if producerBound {
		current, err := control.Policy(ctx, manager)
		if err != nil || current.ID != inputPolicy.ID || current.Hash != inputPolicy.Hash || current.Version != inputPolicy.Version || current.State != "active" {
			t.Fatal("served producer task replaced default ingress", err)
		}
	}
}
