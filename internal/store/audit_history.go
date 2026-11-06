package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type AuditHistoryRequest struct {
	Actor    string   `json:"actor_id,omitempty"`
	Resource string   `json:"resource_id,omitempty"`
	Kinds    []string `json:"kinds,omitempty"`
	From     string   `json:"from,omitempty"`
	Until    string   `json:"until,omitempty"`
	After    string   `json:"after,omitempty"`
	Limit    int      `json:"limit"`
}

type AuditHistoryEvent struct {
	ID       string    `json:"event_id"`
	Actor    string    `json:"actor_id"`
	Kind     string    `json:"kind"`
	Resource string    `json:"resource_id"`
	At       time.Time `json:"recorded_at"`
}

type AuditHistoryPage struct {
	Profile     string              `json:"profile"`
	Tenant      string              `json:"tenant_id"`
	Partner     string              `json:"partner_id"`
	Reader      string              `json:"reader_actor_id"`
	ObservedAt  time.Time           `json:"observed_at"`
	Observation string              `json:"observation"`
	Payloads    string              `json:"payloads"`
	Events      []AuditHistoryEvent `json:"events"`
	Next        string              `json:"next,omitempty"`
}

type auditHistoryCursor struct {
	At      string `json:"at"`
	ID      string `json:"id"`
	Binding string `json:"binding"`
}

var auditHistoryInstant = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$`)
var auditHistoryKind = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,127}$`)

func auditHistoryTime(value string) (time.Time, error) {
	if !auditHistoryInstant.MatchString(value) {
		return time.Time{}, ErrExchangeInput
	}
	v, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || v.Year() < 1 {
		return time.Time{}, ErrExchangeInput
	}
	return v, nil
}

func decodeAuditHistoryCursor(value string) (*auditHistoryCursor, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > 1024 {
		return nil, ErrExchangeInput
	}
	wire, err := base64.RawURLEncoding.Strict().DecodeString(value)
	var c auditHistoryCursor
	if err != nil || base64.RawURLEncoding.EncodeToString(wire) != value || !utf8.Valid(wire) || decodeExchangeJSONBound(wire, &c, 768) != nil || !ValidID(c.ID) || !browserSecretHash.MatchString(c.Binding) {
		return nil, ErrExchangeInput
	}
	if _, err = auditHistoryTime(c.At); err != nil {
		return nil, err
	}
	return &c, nil
}

// Normalize copies the filter list; an asynchronous caller cannot change the
// page query or cursor binding after validation. Limit changes may resize a page.
func NormalizeAuditHistory(r AuditHistoryRequest) (AuditHistoryRequest, error) {
	if r.Limit < 1 || r.Limit > 100 || r.Actor != "" && !ValidID(r.Actor) || r.Resource != "" && !ValidID(r.Resource) || len(r.Kinds) > 16 {
		return AuditHistoryRequest{}, ErrExchangeInput
	}
	for _, kind := range r.Kinds {
		if !auditHistoryKind.MatchString(kind) {
			return AuditHistoryRequest{}, ErrExchangeInput
		}
	}
	r.Kinds = append([]string{}, r.Kinds...)
	slices.Sort(r.Kinds)
	r.Kinds = slices.Compact(r.Kinds)
	for _, raw := range []string{r.From, r.Until} {
		if raw != "" {
			if _, err := auditHistoryTime(raw); err != nil {
				return AuditHistoryRequest{}, err
			}
		}
	}
	if r.From != "" {
		at, _ := auditHistoryTime(r.From)
		r.From = at.Format(time.RFC3339Nano)
	}
	if r.Until != "" {
		at, _ := auditHistoryTime(r.Until)
		r.Until = at.Format(time.RFC3339Nano)
	}
	if r.From != "" && r.Until != "" {
		from, _ := auditHistoryTime(r.From)
		until, _ := auditHistoryTime(r.Until)
		if !from.Before(until) {
			return AuditHistoryRequest{}, ErrExchangeInput
		}
	}
	if _, err := decodeAuditHistoryCursor(r.After); err != nil {
		return AuditHistoryRequest{}, err
	}
	return r, nil
}

func DecodeAuditHistory(raw []byte) (*AuditHistoryRequest, error) {
	var r AuditHistoryRequest
	if !utf8.Valid(raw) || decodeExchangeJSONBound(raw, &r, 8<<10) != nil {
		return nil, ErrExchangeInput
	}
	normalized, err := NormalizeAuditHistory(r)
	return &normalized, err
}

func auditHistoryBinding(t *Transaction, r AuditHistoryRequest) string {
	r.After, r.Limit = "", 0
	wire, _ := json.Marshal(struct {
		Tenant, Partner, Actor, Root string
		Authority                    int64
		Search                       AuditHistoryRequest
	}{t.Scope.Tenant, t.Scope.Partner, t.Actor, secure.Digest([]byte(t.Root)), t.AuthorityRevision, r})
	return secure.Digest(wire)
}

func (s *Store) SearchAuditHistory(ctx context.Context, scope Scope, input AuditHistoryRequest) (*AuditHistoryPage, error) {
	r, err := NormalizeAuditHistory(input)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("audit_read"); err != nil {
		return nil, err
	}
	if t.Root != "/" {
		return nil, ErrForbidden
	}
	binding := auditHistoryBinding(t, r)
	afterAt, afterID := "", ""
	if cursor, _ := decodeAuditHistoryCursor(r.After); cursor != nil {
		if cursor.Binding != binding {
			return nil, ErrConflict
		}
		afterAt, afterID = cursor.At, cursor.ID
	}
	rows, err := t.Tx.Query(ctx, `SELECT event_id::text,actor_id::text,kind,resource_id::text,happened_at FROM events
 WHERE tenant_id=$1 AND partner_id=$2 AND ($3='' OR actor_id=nullif($3,'')::uuid) AND ($4='' OR resource_id=nullif($4,'')::uuid)
 AND (cardinality($5::text[])=0 OR kind=ANY($5::text[]))
 AND ($6='' OR happened_at>=nullif($6,'')::timestamptz) AND ($7='' OR happened_at<nullif($7,'')::timestamptz)
 AND ($8='' OR (happened_at,event_id)>(nullif($8,'')::timestamptz,nullif($9,'')::uuid))
 ORDER BY happened_at,event_id LIMIT $10`, scope.Tenant, scope.Partner, r.Actor, r.Resource, r.Kinds, r.From, r.Until, afterAt, afterID, r.Limit+1)
	if err != nil {
		return nil, err
	}
	page := &AuditHistoryPage{Profile: "event-metadata-history-v1", Tenant: scope.Tenant, Partner: scope.Partner, Reader: t.Actor, Observation: "independent-page-observation", Payloads: "omitted", Events: make([]AuditHistoryEvent, 0, r.Limit)}
	more := false
	for rows.Next() {
		var event AuditHistoryEvent
		if err = rows.Scan(&event.ID, &event.Actor, &event.Kind, &event.Resource, &event.At); err != nil {
			rows.Close()
			return nil, err
		}
		event.At = event.At.UTC()
		if !ValidID(event.ID) || !ValidID(event.Actor) || !ValidID(event.Resource) || len(event.Kind) > 128 || !utf8.ValidString(event.Kind) {
			rows.Close()
			return nil, ErrIsolation
		}
		if len(page.Events) == r.Limit {
			more = true
			break
		}
		page.Events = append(page.Events, event)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if more {
		last := page.Events[len(page.Events)-1]
		wire, _ := json.Marshal(auditHistoryCursor{At: last.At.Format(time.RFC3339Nano), ID: last.ID, Binding: binding})
		page.Next = base64.RawURLEncoding.EncodeToString(wire)
		if _, err = decodeAuditHistoryCursor(page.Next); err != nil {
			return nil, ErrIsolation
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.Require("audit_read"); err != nil || t.Root != "/" {
		if err != nil {
			return nil, err
		}
		return nil, ErrForbidden
	}
	if err = t.Tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&page.ObservedAt); err != nil {
		return nil, err
	}
	page.ObservedAt = page.ObservedAt.UTC()
	return page, t.Tx.Commit(ctx)
}
