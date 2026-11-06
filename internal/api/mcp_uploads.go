package api

import (
	"context"
	"regexp"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

type mcpUploadView struct {
	ID         string `json:"id"`
	Path       string `json:"virtual_path"`
	Size       int64  `json:"expected_size"`
	SHA256     string `json:"expected_sha256"`
	Offset     int64  `json:"committed_offset"`
	Chunks     int    `json:"chunk_count"`
	State      string `json:"state"`
	Revision   int64  `json:"revision"`
	EventID    string `json:"changed_event_id"`
	FileID     string `json:"file_id,omitempty"`
	Acceptance string `json:"acceptance,omitempty"`
}
type mcpUploadDescriptor struct {
	Profile             string        `json:"profile"`
	Upload              mcpUploadView `json:"upload"`
	Observation         string        `json:"observation"`
	CurrentState        string        `json:"current_state"`
	Replayed            bool          `json:"replayed"`
	AppendPath          string        `json:"relative_append_path"`
	AppendMethod        string        `json:"append_method"`
	AppendHeaders       []string      `json:"append_required_headers"`
	MaxChunk            int64         `json:"max_chunk_bytes"`
	MinNonfinalChunk    int64         `json:"min_nonfinal_chunk_bytes"`
	MaxChunks           int           `json:"max_chunks"`
	Authentication      string        `json:"authentication"`
	Availability        string        `json:"artifact_availability"`
	ReceiverPersistence string        `json:"receiver_persistence"`
	BusinessProcessing  string        `json:"business_processing"`
}

var mcpUploadDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func newArtifactUploadRequest(args mcpToolArguments) custody.CreateUpload {
	mode := uint32(0600)
	return custody.CreateUpload{Path: args.Path, Size: args.Size, SHA256: args.SHA256, Mode: &mode}
}

func mcpArtifactUpload(scope store.Scope, u custody.UploadView, receipt, replayed bool) (*mcpUploadDescriptor, error) {
	path, err := vpath.Canonical(u.Path)
	if err != nil || path != u.Path || path == "/" || vpath.ControlPath(path) || !store.ValidID(scope.Tenant) || !store.ValidID(scope.Partner) || !store.ValidID(u.ID) || !store.ValidID(u.EventID) || !mcpUploadDigest.MatchString(u.ExpectedSHA256) || u.ExpectedSize < 0 || u.Offset < 0 || u.Offset > u.ExpectedSize || u.Chunks < 0 || u.Chunks > 4096 || u.Revision < 1 {
		return nil, store.ErrIsolation
	}
	switch u.State {
	case "completed":
		if !store.ValidID(u.FileID) || u.Offset != u.ExpectedSize || (u.Acceptance != "durable-local-integrity-only" && u.Acceptance != "durable-held-pending-checks-and-release") {
			return nil, store.ErrIsolation
		}
	case "open", "aborted", "rejected":
		if u.FileID != "" || u.Acceptance != "" {
			return nil, store.ErrIsolation
		}
	default:
		return nil, store.ErrIsolation
	}
	result := &mcpUploadDescriptor{
		Profile:     "ordinary-resumable-artifact-upload-v1",
		Upload:      mcpUploadView{ID: u.ID, Path: u.Path, Size: u.ExpectedSize, SHA256: u.ExpectedSHA256, Offset: u.Offset, Chunks: u.Chunks, State: u.State, Revision: u.Revision, EventID: u.EventID, FileID: u.FileID, Acceptance: u.Acceptance},
		Observation: "current-ticket-metadata", CurrentState: "observed-ticket-only", Replayed: replayed,
		AppendPath:   "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner + "/uploads/" + u.ID,
		AppendMethod: "PATCH", AppendHeaders: []string{"Content-Type: application/octet-stream", "Upload-Offset", "X-File-Size", "X-Content-SHA256", "Idempotency-Key"}, MaxChunk: custody.MaxUploadChunk, MinNonfinalChunk: custody.MinUploadChunk, MaxChunks: 4096,
		Authentication: "current-ordinary-https-auth", Availability: "not-checked", ReceiverPersistence: "unknown", BusinessProcessing: "unknown",
	}
	if receipt {
		result.Observation = "original-command-receipt"
		result.CurrentState = "not-checked"
	}
	return result, nil
}

// Only metadata enters/leaves MCP. The ordinary service owns transactionality,
// actor/root/revision binding, byte staging, publication and live permissions.
// No overwrite,mode,clock,host path,recipient or credential argument is added.
func (s *Server) mcpArtifactUploadControl(ctx context.Context, scope store.Scope, name string, args mcpToolArguments) (any, error) {
	if name == "freightctl.artifact_upload_status" {
		view, err := s.Service.UploadStatus(ctx, scope, args.Upload)
		if err != nil {
			return nil, err
		}
		return mcpArtifactUpload(scope, *view, false, false)
	}
	var result *custody.UploadResult
	var err error
	switch name {
	case "freightctl.artifact_upload_start":
		result, err = s.Service.CreateUpload(ctx, scope, args.Key, newArtifactUploadRequest(args))
	case "freightctl.artifact_upload_complete":
		result, err = s.Service.CompleteUpload(ctx, scope, args.Upload, args.Key)
	case "freightctl.artifact_upload_abort":
		result, err = s.Service.AbortUpload(ctx, scope, args.Upload, args.Key)
	default:
		return nil, store.ErrExchangeInput
	}
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, store.ErrIsolation
	}
	return mcpArtifactUpload(scope, result.Upload, true, result.Replayed)
}
