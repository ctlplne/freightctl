//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestWebDAVConditionalCreateIsAtomicAndKeepsHeldAcceptanceSeparate(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	headers := func(key string, data []byte) map[string]string {
		return map[string]string{"Authorization": "Bearer " + string(admin.Bytes), "If-None-Match": "*", "Idempotency-Key": key, "X-Content-SHA256": secure.Digest(data)}
	}
	data := []byte("exact conditional DAV bytes\n")
	path := prefix + "/dav/created.dat"
	response, raw := exchangeAPIRequest(t, server, "PUT", path, nil, headers("dav-create", data), data, 201)
	var receipt struct {
		File       store.File `json:"file"`
		Replayed   bool       `json:"replayed"`
		Acceptance string     `json:"acceptance"`
		Namespace  string     `json:"namespace_state"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.Replayed || receipt.Namespace != "published-at-commit" || receipt.File.SHA256 != secure.Digest(data) || response.Header.Get("ETag") != artifactRevisionETag(&receipt.File) {
		t.Fatal("conditional DAV creation did not bind its exact published immutable revision")
	}
	for _, key := range []string{"dav-create", "dav-create-another"} {
		response, _ = exchangeAPIRequest(t, server, "PUT", path, nil, headers(key, data), data, 412)
		if response.Header.Get("ETag") != "" {
			t.Fatal("refused conditional retry invented a current validator")
		}
	}
	_, readback := exchangeAPIRequest(t, server, "GET", path, nil, map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}, nil, 200)
	if !bytes.Equal(readback, data) {
		t.Fatal("conditional retry changed the published bytes")
	}
	reader, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	denied := headers("dav-read-only-create", data)
	denied["Authorization"] = "Bearer " + string(reader.Bytes)
	exchangeAPIRequest(t, server, "PUT", prefix+"/dav/denied.dat", nil, denied, data, 403)
	// Two real concurrent transactions contend for the same absent path. Only
	// one may stage/acknowledge a published file;the other must fail its condition.
	type outcome struct {
		index, status int
		err           error
	}
	results := make(chan outcome, 2)
	inputs := [][]byte{[]byte("first racing source"), []byte("second racing source")}
	for index, input := range inputs {
		go func(index int, input []byte) {
			r, err := http.NewRequestWithContext(t.Context(), "PUT", server.URL+prefix+"/dav/race.dat", bytes.NewReader(input))
			if err != nil {
				results <- outcome{index: index, err: err}
				return
			}
			for key, value := range headers("dav-race-"+strconv.Itoa(index), input) {
				r.Header.Set(key, value)
			}
			response, err := server.Client().Do(r)
			if err != nil {
				results <- outcome{index: index, err: err}
				return
			}
			_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 65537))
			closeErr := response.Body.Close()
			if readErr != nil {
				err = readErr
			} else {
				err = closeErr
			}
			results <- outcome{index: index, status: response.StatusCode, err: err}
		}(index, input)
	}
	winner, created, refused := -1, 0, 0
	for range 2 {
		r := <-results
		if r.err != nil {
			t.Fatal("actual concurrent DAV request failed")
		}
		switch r.status {
		case 201:
			created++
			winner = r.index
		case 412:
			refused++
		default:
			t.Fatalf("concurrent conditional status=%d", r.status)
		}
	}
	if created != 1 || refused != 1 || winner < 0 {
		t.Fatal("two conditional writes did not have exactly one namespace winner")
	}
	_, readback = exchangeAPIRequest(t, server, "GET", prefix+"/dav/race.dat", nil, map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}, nil, 200)
	if !bytes.Equal(readback, inputs[winner]) {
		t.Fatal("published race winner differs from the acknowledged bytes")
	}
	checking := &checks.Service{Custody: service}
	if _, err := checking.Register(t.Context(), scope, "dav-create-policy", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	held := []byte("record\nheld until separately released\n")
	heldPath := prefix + "/dav/held.csv"
	heldHeaders := headers("dav-create-held", held)
	response, raw = exchangeAPIRequest(t, server, "PUT", heldPath, nil, heldHeaders, held, 202)
	if json.Unmarshal(raw, &receipt) != nil || receipt.Replayed || receipt.Acceptance != "durable-held-pending-checks-and-release" || receipt.Namespace != "not-published-at-acceptance" || response.Header.Get("ETag") != "" {
		t.Fatal("held acceptance was represented as DAV publication")
	}
	heldFile := receipt.File
	response, raw = exchangeAPIRequest(t, server, "PUT", heldPath, nil, heldHeaders, held, 200)
	if json.Unmarshal(raw, &receipt) != nil || !receipt.Replayed || receipt.File.ID != heldFile.ID || receipt.Namespace != "not-asserted-original-receipt" || response.Header.Get("ETag") != "" {
		t.Fatal("held retry did not recover only its original acceptance receipt")
	}
	auth := map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}
	exchangeAPIRequest(t, server, "GET", heldPath, nil, auth, nil, 404)
	if _, err := checking.Run(t.Context(), scope, heldFile.ID, "dav-create-held-check"); err != nil {
		t.Fatal(err)
	}
	checked, err := checking.Get(t.Context(), scope, heldFile.ID)
	if err != nil || checked.Check.State != "passed" {
		t.Fatal("held DAV file did not pass ordinary checks", err)
	}
	exchangeAPIRequest(t, server, "GET", heldPath, nil, auth, nil, 404)
	if _, err = checking.Release(t.Context(), scope, heldFile.ID, "dav-create-held-release", checks.ReleaseDecision{SHA256: heldFile.SHA256, PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	_, readback = exchangeAPIRequest(t, server, "GET", heldPath, nil, auth, nil, 200)
	if !bytes.Equal(readback, held) {
		t.Fatal("separately released DAV bytes differ")
	}
	exchangeAPIRequest(t, server, "PUT", heldPath, nil, heldHeaders, held, 412)
	tx, err := service.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var files, intents, runs int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM files),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`).Scan(&files, &intents, &runs); err != nil || files != 3 || intents != 0 || runs != 0 {
		t.Fatal("conditional/held retries created duplicate files or forwarding/execution effects", err)
	}
}
