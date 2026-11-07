package store

import "encoding/json"

func privateProcessingEvent(e Event) bool {
	switch e.Kind {
	case "ProcessingOutputPolicyBound", "ProcessingWorkflowReviewChanged", "WorkflowProcessingBound", "RecordProjectionChanged":
		return true
	}
	type definition struct {
		Processing json.RawMessage `json:"processing"`
	}
	var p struct {
		State            string          `json:"state"`
		Definition       definition      `json:"definition"`
		RecordProjection json.RawMessage `json:"record_projection"`
		Result           struct {
			Kind              string          `json:"kind"`
			Profile           string          `json:"profile"`
			Definition        definition      `json:"definition"`
			Processing        json.RawMessage `json:"processing"`
			ProcessingAttempt json.RawMessage `json:"processing_attempt"`
			Projection        json.RawMessage `json:"projection"`
			Review            json.RawMessage `json:"review"`
		} `json:"result"`
	}
	if json.Unmarshal(e.Payload, &p) != nil {
		return false
	}
	present := func(raw json.RawMessage) bool { return len(raw) > 0 && string(raw) != "null" }
	if present(p.Definition.Processing) || present(p.Result.Definition.Processing) {
		return true
	}
	if e.Kind == "IntakePolicyChanged" {
		return p.State == "output_active" || p.State == "output_retired" || p.State == "output_revoked"
	}
	if e.Kind == "FileAccepted" && present(p.RecordProjection) {
		return true
	}
	if e.Kind == "CheckCommandCompleted" || e.Kind == "WorkflowCommandCompleted" {
		return p.Result.Profile == "producer-processing-output-policy-v1" || p.Result.Profile == "independent-processing-workflow-review-v1" || p.Result.Profile == "owned-record-processing-schedule-v1" || p.Result.Kind == "record_projection" || present(p.Result.Processing) || present(p.Result.ProcessingAttempt) || present(p.Result.Projection) || present(p.Result.Review)
	}
	return false
}
