package assistance

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func eventFor(ctx context.Context, t *store.Transaction, kind, id string, version int) (Citation, error) {
	table, column := "", ""
	switch kind {
	case "connection":
		table, column = "connection_revisions", "connection_id"
	case "workflow":
		table, column = "workflow_revisions", "workflow_id"
	case "run":
		table, column = "workflow_runs", "run_id"
	case "delivery":
		table, column = "delivery_intents", "delivery_id"
	default:
		return Citation{}, ErrInput
	}
	query := `SELECT e.event_id::text,e.kind,e.resource_id::text FROM ` + table + ` p JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(p.tenant_id,p.partner_id,p.changed_event_id) WHERE p.` + column + `=$1 AND p.actor_id=$2 AND e.actor_id=$2`
	args := []any{id, t.Actor}
	if version > 0 {
		query += ` AND p.version=$3`
		args = append(args, version)
	}
	c := Citation{}
	err := t.Tx.QueryRow(ctx, query, args...).Scan(&c.EventID, &c.Kind, &c.ResourceID)
	return c, err
}
func profile(ctx context.Context, t *store.Transaction, ref workflow.Reference, active bool) (*store.Configuration, *Profile, error) {
	if !store.ValidID(ref.ID) || ref.Version < 1 || !hashPattern.MatchString(ref.Hash) {
		return nil, nil, ErrInput
	}
	row, err := t.AIProfile(ctx, ref.ID, ref.Version, false)
	if err != nil {
		return nil, nil, err
	}
	if row.Hash != ref.Hash {
		return nil, nil, store.ErrRevision
	}
	if active && row.State != "active" {
		return nil, nil, store.ErrState
	}
	var p Profile
	if json.Unmarshal(row.Definition, &p) != nil {
		return nil, nil, store.ErrState
	}
	p, err = normalizeProfile(p)
	if err != nil {
		return nil, nil, err
	}
	_, hash, err := canonical(p)
	if err != nil || hash != row.Hash {
		return nil, nil, store.ErrState
	}
	return row, &p, nil
}
func buildContext(ctx context.Context, t *store.Transaction, r PrepareRequest, p *Profile, initial bool) (*Context, *Bindings, error) {
	c := &Context{Schema: 1, Kind: r.Kind}
	b := &Bindings{Request: r, Snapshots: []Snapshot{}, Evidence: map[string][]Citation{}}
	labels := []string{r.Name}
	add := func(kind, id string, version int, revision int64, hash string) (Citation, error) {
		cite, err := eventFor(ctx, t, kind, id, version)
		if err != nil {
			return cite, err
		}
		b.Snapshots = append(b.Snapshots, Snapshot{Kind: kind, ID: id, Version: version, Revision: revision, Hash: hash, EventID: cite.EventID})
		return cite, nil
	}
	if r.Requirements != "" && !p.AllowOperatorText {
		return nil, nil, store.ErrForbidden
	}
	switch r.Kind {
	case "propose":
		if err := t.Require("workflow_manage"); err != nil {
			return nil, nil, err
		}
		if r.RunID != "" || len(r.Destinations) < 1 || len(r.Destinations) > 16 {
			return nil, nil, ErrInput
		}
		draft := workflow.Definition{Schema: 1, Name: r.Name, Steps: []workflow.Step{}}
		for i, d := range r.Destinations {
			if !store.ValidID(d.Connection.ID) || d.Connection.Version < 1 || !hashPattern.MatchString(d.Connection.Hash) {
				return nil, nil, ErrInput
			}
			conn, err := t.Configuration(ctx, true, d.Connection.ID, d.Connection.Version, false)
			if err != nil {
				return nil, nil, err
			}
			if conn.State != "active" {
				return nil, nil, store.ErrState
			}
			if conn.Hash != d.Connection.Hash {
				return nil, nil, store.ErrRevision
			}
			if _, err = add("connection", conn.ID, conn.Version, conn.Revision, conn.Hash); err != nil {
				return nil, nil, err
			}
			// Registered transport details remain bindings, never model context.
			var def workflow.ConnectionDefinition
			if json.Unmarshal(conn.Definition, &def) != nil {
				return nil, nil, store.ErrState
			}
			labels = append(labels, d.Filename, def.Directory, def.Destination.Address, def.Destination.KeyFile, def.Destination.User)
			alias := "d" + strconv.Itoa(i+1)
			c.Destinations = append(c.Destinations, alias)
			draft.Steps = append(draft.Steps, workflow.Step{ID: "deliver_" + strconv.Itoa(i+1), Kind: "sftp.deliver", Connection: d.Connection, Filename: d.Filename})
		}
		normalized, err := workflow.Normalize(draft)
		if err != nil {
			return nil, nil, err
		}
		b.Request.Name = normalized.Name
	case "diagnose":
		if r.Name != "" || len(r.Destinations) != 0 || !store.ValidID(r.RunID) {
			return nil, nil, ErrInput
		}
		if !t.Has("workflow_manage") && !t.Has("workflow_approve") && !t.Has("workflow_execute") {
			return nil, nil, store.ErrForbidden
		}
		if err := t.Require("read"); err != nil {
			return nil, nil, err
		}
		run, err := t.WorkflowRun(ctx, r.RunID, false)
		if err != nil {
			return nil, nil, err
		}
		if err = t.FileAccessible(ctx, run.FileID); err != nil {
			return nil, nil, err
		}
		runCite, err := add("run", run.ID, 0, run.Revision, run.WorkflowHash)
		if err != nil {
			return nil, nil, err
		}
		fact := func(code string, cites ...Citation) string {
			alias := "e" + strconv.Itoa(len(c.Facts)+1)
			c.Facts = append(c.Facts, Fact{Alias: alias, Code: code})
			b.Evidence[alias] = cites
			return alias
		}
		finding := func(code, next string, cites ...Citation) {
			alias := fact(code, cites...)
			c.Supported = append(c.Supported, Finding{Code: code, Evidence: []string{alias}, NextCheck: next})
		}
		wf, err := t.Configuration(ctx, false, run.WorkflowID, run.WorkflowVersion, false)
		if err != nil {
			return nil, nil, err
		}
		wfCite, err := add("workflow", wf.ID, wf.Version, wf.Revision, wf.Hash)
		if err != nil {
			return nil, nil, err
		}
		var definition workflow.Definition
		if json.Unmarshal(wf.Definition, &definition) != nil {
			return nil, nil, store.ErrState
		}
		labels = append(labels, definition.Name)
		for _, step := range definition.Steps {
			labels = append(labels, step.Filename)
		}
		if run.State == "cancelled" {
			finding("run_cancelled", "inspect_dispatch", runCite)
		}
		if wf.State != "approved" {
			finding("workflow_revoked", "review_approval", wfCite)
		}
		steps, err := t.WorkflowSteps(ctx, run.ID)
		if err != nil {
			return nil, nil, err
		}
		if len(steps) < 1 {
			return nil, nil, store.ErrState
		}
		completed := []Citation{}
		allQueued := true
		seenConns := map[string]bool{}
		for _, step := range steps {
			d, err := t.Delivery(ctx, step.DeliveryID, false)
			if err != nil {
				return nil, nil, err
			}
			cite, err := add("delivery", d.ID, 0, d.Revision, d.DefinitionHash)
			if err != nil {
				return nil, nil, err
			}
			var observation struct {
				Code string `json:"code"`
				SHA  string `json:"sha256"`
				Size int64  `json:"size_bytes"`
			}
			if json.Unmarshal(d.Observation, &observation) != nil {
				return nil, nil, store.ErrState
			}
			if d.Attempts != 0 || d.State != "queued" {
				allQueued = false
			}
			switch {
			case d.State == "ambiguous":
				finding("uncertain_delivery", "read_only_reconcile", cite)
			case d.State == "publishing":
				finding("publication_pending", "inspect_receipt", cite)
			case observation.Code == "receiver_connection_failed":
				finding("connection_not_established", "check_receiver_trust_and_network", cite)
			case observation.Code == "source_not_verified" || observation.Code == "source_changed_during_delivery":
				finding("source_not_verified", "inspect_custody", cite)
			case d.State == "blocked":
				finding("delivery_blocked", "inspect_delivery", cite)
			case d.State == "staging":
				finding("dispatch_in_progress", "inspect_delivery", cite)
			}
			if d.State == "succeeded" {
				if observation.Code != "remote_file_integrity_observed" || observation.SHA != run.Source.SHA256 || observation.Size != run.Source.Size {
					return nil, nil, store.ErrState
				}
				completed = append(completed, cite)
			}
			connKey := step.ConnectionID + ":" + strconv.Itoa(step.ConnectionVersion)
			if !seenConns[connKey] {
				seenConns[connKey] = true
				conn, err := t.Configuration(ctx, true, step.ConnectionID, step.ConnectionVersion, false)
				if err != nil {
					return nil, nil, err
				}
				cc, err := add("connection", conn.ID, conn.Version, conn.Revision, conn.Hash)
				if err != nil {
					return nil, nil, err
				}
				if conn.State != "active" {
					finding("connection_revoked", "review_approval", cc)
				}
				var def workflow.ConnectionDefinition
				if json.Unmarshal(conn.Definition, &def) != nil {
					return nil, nil, store.ErrState
				}
				labels = append(labels, def.Directory, def.Destination.Address, def.Destination.KeyFile, def.Destination.User)
			}
		}
		if len(completed) == len(steps) {
			finding("transport_complete", "obtain_business_receipt", completed...)
		} else if allQueued && len(c.Supported) == 0 {
			if run.State == "queued" {
				finding("awaiting_worker", "inspect_dispatch", runCite)
			} else if run.State == "running" {
				finding("dispatch_prepared", "inspect_dispatch", runCite)
			}
		}
	default:
		return nil, nil, ErrInput
	}
	if initial {
		// Scrub recognizable secrets first, then replace known resource labels in
		// one pass so aliases themselves are never reinterpreted as private labels.
		text, err := redact(r.Requirements, nil)
		if err != nil {
			return nil, nil, err
		}
		replacements := map[string]string{}
		for _, label := range labels {
			if label != "" {
				replacements[label] = "[label redacted]"
			}
		}
		counts := map[string]int{}
		for _, destination := range r.Destinations {
			counts[destination.Filename]++
		}
		for i, destination := range r.Destinations {
			if counts[destination.Filename] == 1 {
				replacements[destination.Filename] = "d" + strconv.Itoa(i+1)
			}
		}
		keys := make([]string, 0, len(replacements))
		for key := range replacements {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			if len(keys[i]) == len(keys[j]) {
				return keys[i] < keys[j]
			}
			return len(keys[i]) > len(keys[j])
		})
		pairs := []string{}
		for _, key := range keys {
			pairs = append(pairs, key, replacements[key])
		}
		if len(pairs) > 0 {
			text = strings.NewReplacer(pairs...).Replace(text)
		}
		b.Request.Requirements = text
	}
	c.Requirements = b.Request.Requirements
	data, _, err := canonical(c)
	if err != nil {
		return nil, nil, err
	}
	if len(data) > p.ContextBytes {
		return nil, nil, store.ErrLimit
	}
	data, _, err = canonical(b)
	if err != nil {
		return nil, nil, err
	}
	if len(data) > 24<<10 {
		return nil, nil, store.ErrLimit
	}
	return c, b, nil
}

var explanations = map[string]string{
	"workflow_revoked":           "The workflow approval is revoked. A new authorization decision is required before execution.",
	"connection_revoked":         "A connection version referenced by this run is revoked. The run is frozen; a newer version does not alter it.",
	"uncertain_delivery":         "The delivery outcome is recorded as uncertain. The receiver may already have bytes; do not resend without resolving the recorded receipt.",
	"publication_pending":        "Publication was authorized but a final integrity receipt is not recorded. Inspect current lease and receipt state; business acceptance is unknown.",
	"connection_not_established": "The worker could not establish the configured receiver connection. Host trust, identity, negotiation or network failure may be responsible; the evidence does not confirm which.",
	"source_not_verified":        "The worker could not verify the exact accepted source bytes. Inspect custody; this event alone does not distinguish missing data from corruption.",
	"delivery_blocked":           "The delivery is blocked. Inspect its recorded outcome before preparing any recovery.",
	"dispatch_in_progress":       "The worker is staging an approved delivery. No final delivery receipt is established by this state.",
	"transport_complete":         "Every step has a recorded observation of the exact remote file integrity. Downstream business acceptance remains unknown.",
	"awaiting_worker":            "The run is queued with no delivery attempt recorded. Inspect or prepare the ordinary authorized dispatch.",
	"dispatch_prepared":          "A workflow dispatch is recorded, but no delivery attempt is recorded yet. Inspect the same selected dispatch before preparing another action.",
	"run_cancelled":              "The run is cancelled by an operator decision. This does not undo any already recorded external effect.",
	"insufficient_evidence":      "The supplied evidence does not support a specific diagnosis. Gather current authorized receipts and state before deciding on recovery.",
}

func validateOutput(j *store.AIJob, output string) (*ValidatedResult, error) {
	var c Context
	var b Bindings
	if json.Unmarshal(j.Context, &c) != nil || json.Unmarshal(j.Bindings, &b) != nil {
		return nil, store.ErrState
	}
	if j.Kind == "propose" {
		var proposal Proposal
		if workflow.Decode([]byte(output), &proposal) != nil {
			return nil, ErrModelOutput
		}
		allowedMissing := []string{"sequence", "destination", "filename", "supported_task", "business_receipt_contract"}
		for _, code := range proposal.Missing {
			if !slices.Contains(allowedMissing, code) {
				return nil, ErrModelOutput
			}
		}
		if proposal.Status == "ready" {
			if len(proposal.Missing) != 0 || len(proposal.Order) != len(c.Destinations) {
				return nil, ErrModelOutput
			}
			seen := map[string]bool{}
			for _, alias := range proposal.Order {
				if seen[alias] || !slices.Contains(c.Destinations, alias) {
					return nil, ErrModelOutput
				}
				seen[alias] = true
			}
		} else if proposal.Status == "needs_input" || proposal.Status == "unsupported" {
			if len(proposal.Order) != 0 || len(proposal.Missing) == 0 {
				return nil, ErrModelOutput
			}
		} else {
			return nil, ErrModelOutput
		}
		return &ValidatedResult{Proposal: &proposal}, nil
	}
	var diagnosis Diagnosis
	if workflow.Decode([]byte(output), &diagnosis) != nil {
		return nil, ErrModelOutput
	}
	if diagnosis.Code == "insufficient_evidence" {
		if len(diagnosis.Evidence) != 0 || diagnosis.NextCheck != "gather_evidence" {
			return nil, ErrModelOutput
		}
		return &ValidatedResult{Diagnosis: &diagnosis, Explanation: explanations[diagnosis.Code]}, nil
	}
	for _, finding := range c.Supported {
		if finding.Code != diagnosis.Code || finding.NextCheck != diagnosis.NextCheck || len(finding.Evidence) != len(diagnosis.Evidence) {
			continue
		}
		same := true
		for _, alias := range finding.Evidence {
			if !slices.Contains(diagnosis.Evidence, alias) {
				same = false
			}
		}
		if !same {
			continue
		}
		citations := []Citation{}
		seen := map[string]bool{}
		for _, alias := range diagnosis.Evidence {
			for _, cite := range b.Evidence[alias] {
				if !seen[cite.EventID] {
					citations = append(citations, cite)
					seen[cite.EventID] = true
				}
			}
		}
		if len(citations) == 0 {
			return nil, ErrModelOutput
		}
		return &ValidatedResult{Diagnosis: &diagnosis, Explanation: explanations[diagnosis.Code], Citations: citations}, nil
	}
	return nil, ErrModelOutput
}
func proposedDefinition(j *store.AIJob) (workflow.Definition, error) {
	var b Bindings
	var result ValidatedResult
	if json.Unmarshal(j.Bindings, &b) != nil || json.Unmarshal(j.Result, &result) != nil || result.Proposal == nil || result.Proposal.Status != "ready" {
		return workflow.Definition{}, store.ErrState
	}
	proposalBytes, _, err := canonical(result.Proposal)
	if err != nil {
		return workflow.Definition{}, err
	}
	if _, err = validateOutput(j, string(proposalBytes)); err != nil {
		return workflow.Definition{}, err
	}
	d := workflow.Definition{Schema: 1, Name: b.Request.Name, Steps: []workflow.Step{}}
	for i, alias := range result.Proposal.Order {
		var n int
		if _, err := fmt.Sscanf(alias, "d%d", &n); err != nil || n < 1 || n > len(b.Request.Destinations) || alias != "d"+strconv.Itoa(n) {
			return d, ErrModelOutput
		}
		target := b.Request.Destinations[n-1]
		d.Steps = append(d.Steps, workflow.Step{ID: "deliver_" + strconv.Itoa(i+1), Kind: "sftp.deliver", Connection: target.Connection, Filename: target.Filename})
	}
	return workflow.Normalize(d)
}
