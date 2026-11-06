package custody

import (
	"context"
	"strconv"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

type IngressDescriptorRequest struct {
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
	Key    string `json:"request_key"`
}
type IngressDescriptor struct {
	Profile             string                   `json:"profile"`
	Request             IngressDescriptorRequest `json:"request"`
	Method              string                   `json:"method"`
	Path                string                   `json:"relative_path"`
	Headers             map[string]string        `json:"headers"`
	Authentication      string                   `json:"authentication"`
	State               string                   `json:"state"`
	Availability        string                   `json:"availability"`
	AcceptancePolicy    string                   `json:"acceptance_policy"`
	ReceiverPersistence string                   `json:"receiver_persistence"`
	BusinessProcessing  string                   `json:"business_processing"`
}

func validateIngressDescriptor(r IngressDescriptorRequest, maxFile int64) error {
	if maxFile < 0 || r.Size < 0 || r.Size > maxFile || !digestPattern.MatchString(r.SHA256) || !keyPattern.MatchString(r.Key) {
		return ErrInput
	}
	return nil
}

// Preparation supplies metadata,never an upload grant,reservation or receipt.
// The existing Accept operation repeats its own live permissions,capacity,
// policy,exact-body integrity and durable acceptance transaction. No bytes enter
// this control operation and no host path,address or credential can be supplied.
func (s *Service) PrepareArtifactIngress(ctx context.Context, scope store.Scope, r IngressDescriptorRequest) (*IngressDescriptor, error) {
	if err := validateIngressDescriptor(r, s.MaxFile); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("write"); err != nil {
		return nil, err
	}
	// This is exactly the existing unnamed-custody acceptance profile. It does
	// not invent a namespace target for a confined participant.
	if t.Root != "/" {
		return nil, store.ErrForbidden
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	result := &IngressDescriptor{Profile: "ordinary-custody-upload-descriptor-v1", Request: r, Method: "POST", Path: "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner + "/files", Headers: map[string]string{"Content-Type": "application/octet-stream", "X-File-Size": strconv.FormatInt(r.Size, 10), "X-Content-SHA256": r.SHA256, "Idempotency-Key": r.Key}, Authentication: "current-ordinary-https-auth", State: "metadata-only", Availability: "not-checked", AcceptancePolicy: "evaluated-by-upload-service", ReceiverPersistence: "unknown", BusinessProcessing: "unknown"}
	return result, t.Tx.Rollback(ctx)
}
