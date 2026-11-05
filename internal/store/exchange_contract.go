package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

var ErrExchangeInput = errors.New("invalid artifact exchange contract")

// These are explicit request bindings, never authentication proofs or grants.
// The exchange service must authenticate and recheck all referenced live state.
type ExchangeParticipant struct {
	Tenant            string `json:"tenant_id"`
	Partner           string `json:"partner_id"`
	Actor             string `json:"actor_id"`
	AuthorityRevision int64  `json:"authority_revision"`
	RootPolicyDigest  string `json:"root_policy_digest"`
}

// The first endpoint is a registered custody view, not a URL, host path,
// notification subscription or permission to contact an arbitrary recipient.
type ExchangeEndpointDefinition struct {
	Schema    int                   `json:"schema_version"`
	Profile   string                `json:"profile"`
	Recipient ExchangeParticipant   `json:"recipient"`
	Senders   []ExchangeParticipant `json:"senders"`
}

type ExchangeEndpointReference struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Hash     string `json:"hash"`
}

// ID identifies the immutable custody revision, not a mutable namespace path.
// Policy is its original acceptance policy, not a caller's assertion of "clean".
type ExchangeArtifact struct {
	ID     string `json:"file_revision_id"`
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
	Policy string `json:"acceptance_policy"`
}

type ExchangeRequest struct {
	Schema    int                       `json:"schema_version"`
	Artifact  ExchangeArtifact          `json:"artifact"`
	Endpoint  ExchangeEndpointReference `json:"endpoint"`
	ExpiresAt time.Time                 `json:"expires_at"`
	Receipt   string                    `json:"receipt"`
	ReplyTo   string                    `json:"reply_to,omitempty"`
}

// Operational admission controls, not edition limits. The service supplies
// configured values; a caller cannot expand them in an exchange request.
type ExchangeLimits struct {
	MaxArtifactBytes int64
	MaxLifetime      time.Duration
	MaxSenders       int
}

func (limits ExchangeLimits) valid() bool {
	return limits.MaxArtifactBytes >= 0 && limits.MaxLifetime > 0 && limits.MaxSenders >= 1 && limits.MaxSenders <= 128
}

func validExchangeParticipant(p ExchangeParticipant) bool {
	return ValidID(p.Tenant) && ValidID(p.Partner) && ValidID(p.Actor) && p.AuthorityRevision > 0 && browserSecretHash.MatchString(p.RootPolicyDigest)
}

func CanonicalExchangeEndpoint(d ExchangeEndpointDefinition, limits ExchangeLimits) ([]byte, string, error) {
	if !limits.valid() || d.Schema != 1 || d.Profile != "custody-https-poll-v1" || !validExchangeParticipant(d.Recipient) || len(d.Senders) < 1 || len(d.Senders) > limits.MaxSenders {
		return nil, "", ErrExchangeInput
	}
	d.Senders = slices.Clone(d.Senders)
	slices.SortFunc(d.Senders, func(a, b ExchangeParticipant) int { return strings.Compare(a.Actor, b.Actor) })
	for i, sender := range d.Senders {
		if !validExchangeParticipant(sender) || sender.Tenant != d.Recipient.Tenant || sender.Partner != d.Recipient.Partner || i > 0 && sender.Actor == d.Senders[i-1].Actor {
			return nil, "", ErrExchangeInput
		}
	}
	return exchangeCanonical(d)
}

func CanonicalExchangeRequest(r ExchangeRequest, limits ExchangeLimits) ([]byte, string, error) {
	policy := r.Artifact.Policy == "integrity-only-v1" || strings.HasPrefix(r.Artifact.Policy, "intake-csv-v1:") && browserSecretHash.MatchString(strings.TrimPrefix(r.Artifact.Policy, "intake-csv-v1:"))
	if !limits.valid() || r.Schema != 1 || !ValidID(r.Artifact.ID) || r.Artifact.Size < 0 || r.Artifact.Size > limits.MaxArtifactBytes || !browserSecretHash.MatchString(r.Artifact.SHA256) || !policy || !ValidID(r.Endpoint.ID) || r.Endpoint.Revision < 1 || !browserSecretHash.MatchString(r.Endpoint.Hash) || r.ExpiresAt.IsZero() || r.ExpiresAt.Nanosecond()%1000 != 0 || r.Receipt != "availability-only-v1" || r.ReplyTo != "" && !ValidID(r.ReplyTo) {
		return nil, "", ErrExchangeInput
	}
	r.ExpiresAt = r.ExpiresAt.UTC()
	return exchangeCanonical(r)
}

// ValidateAdmission applies to a new exchange only. Canonical decoding does not
// turn an expired request into a different meaning: a receipt replay can identify
// the original exchange, while live authorization still gates every byte access.
func (r ExchangeRequest) ValidateAdmission(now time.Time, limits ExchangeLimits) error {
	if _, _, err := CanonicalExchangeRequest(r, limits); err != nil {
		return err
	}
	if now.IsZero() || !r.ExpiresAt.After(now) || r.ExpiresAt.Sub(now) > limits.MaxLifetime {
		return ErrExchangeInput
	}
	return nil
}

func exchangeCanonical(value any) ([]byte, string, error) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > 16<<10 {
		return nil, "", ErrExchangeInput
	}
	return data, secure.Digest(data), nil
}

func DecodeExchangeRequest(raw []byte, limits ExchangeLimits) (*ExchangeRequest, []byte, string, error) {
	var request ExchangeRequest
	if err := decodeExchangeJSON(raw, &request); err != nil {
		return nil, nil, "", err
	}
	canonical, hash, err := CanonicalExchangeRequest(request, limits)
	if err != nil {
		return nil, nil, "", err
	}
	request.ExpiresAt = request.ExpiresAt.UTC()
	return &request, canonical, hash, nil
}

func DecodeExchangeEndpoint(raw []byte, limits ExchangeLimits) (*ExchangeEndpointDefinition, []byte, string, error) {
	var definition ExchangeEndpointDefinition
	if err := decodeExchangeJSON(raw, &definition); err != nil {
		return nil, nil, "", err
	}
	canonical, hash, err := CanonicalExchangeEndpoint(definition, limits)
	if err != nil {
		return nil, nil, "", err
	}
	// Return the same sorted, independent sender set as the persisted meaning.
	if json.Unmarshal(canonical, &definition) != nil {
		return nil, nil, "", ErrExchangeInput
	}
	return &definition, canonical, hash, nil
}

func decodeExchangeJSON(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > 16<<10 {
		return ErrExchangeInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var walk func(int) error
	walk = func(depth int) error {
		tokens++
		if depth > 8 || tokens > 4096 {
			return ErrExchangeInput
		}
		token, err := d.Token()
		if err != nil || token == nil {
			return ErrExchangeInput
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				token, err := d.Token()
				key, ok := token.(string)
				if err != nil || !ok || seen[key] {
					return ErrExchangeInput
				}
				// encoding/json accepts case-folded struct-field aliases. Require
				// the ASCII spelling used by this contract before typed decoding,
				// including refusal of Unicode folds such as long-s -> S.
				for _, character := range key {
					if character != '_' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
						return ErrExchangeInput
					}
				}
				seen[key] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return ErrExchangeInput
			}
		case json.Delim('['):
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return ErrExchangeInput
			}
		case json.Delim('}'), json.Delim(']'):
			return ErrExchangeInput
		}
		return nil
	}
	if walk(0) != nil {
		return ErrExchangeInput
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrExchangeInput
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return ErrExchangeInput
	}
	return nil
}
