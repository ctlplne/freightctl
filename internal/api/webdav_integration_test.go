//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestWebDAVReadsUsePublishedNamespaceModesIntakeAndCurrentAuthority(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	auth := map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}
	commandHeaders := map[string]string{"Authorization": auth["Authorization"], "Idempotency-Key": "dav-folder"}
	exchangeAPIRequest(t, server, "POST", prefix+"/namespace/commands", nil, commandHeaders, exchangeAPIJSON(t, store.PathCommand{Operation: "mkdir", Path: "/folder"}), 200)
	data := []byte("ordinary immutable artifact; DAV adds no forwarding authority\n")
	virtual := "/folder/a & b.txt"
	headers := map[string]string{"Authorization": auth["Authorization"], "Idempotency-Key": "dav-publish", "X-File-Size": strconv.Itoa(len(data)), "X-Content-SHA256": secure.Digest(data)}
	_, raw := exchangeAPIRequest(t, server, "PUT", prefix+"/namespace/file?path="+url.QueryEscape(virtual), nil, headers, data, 201)
	var accepted struct {
		File store.File `json:"file"`
	}
	if json.Unmarshal(raw, &accepted) != nil || accepted.File.SHA256 != secure.Digest(data) {
		t.Fatal("ordinary DAV source acceptance differs")
	}
	reader, actor := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	dav := prefix + "/dav/folder/"
	readerHeaders := map[string]string{"Authorization": "Bearer " + string(reader.Bytes), "Depth": "1", "Content-Type": "application/xml"}
	request := []byte(`<propfind xmlns="DAV:" xmlns:x="urn:untrusted"><prop><getetag/><resourcetype/><getcontentlength/><x:execute/></prop></propfind>`)
	response, raw := exchangeAPIRequest(t, server, "PROPFIND", dav, nil, readerHeaders, request, 207)
	var result struct {
		Responses []struct {
			Href   string `xml:"DAV: href"`
			Groups []struct {
				Status string `xml:"DAV: status"`
				Prop   struct {
					ETag    string    `xml:"DAV: getetag"`
					Size    string    `xml:"DAV: getcontentlength"`
					Execute *struct{} `xml:"urn:untrusted execute"`
				} `xml:"DAV: prop"`
			} `xml:"DAV: propstat"`
		} `xml:"DAV: response"`
	}
	if xml.Unmarshal(raw, &result) != nil || len(result.Responses) != 2 || response.Header.Get("Cache-Control") != "no-store" || result.Responses[1].Href != dav+"a%20&%20b.txt" || result.Responses[1].Groups[0].Prop.Size != strconv.Itoa(len(data)) || result.Responses[1].Groups[1].Status != "HTTP/1.1 404 Not Found" || result.Responses[1].Groups[1].Prop.Execute == nil {
		t.Fatal("DAV discovery changed exact namespace, properties or unknown-property refusal")
	}
	fileURL := dav + "a%20%26%20b.txt"
	response, body := exchangeAPIRequest(t, server, "GET", fileURL, nil, readerHeaders, nil, 200)
	etag := response.Header.Get("ETag")
	if !bytes.Equal(body, data) || etag != result.Responses[1].Groups[0].Prop.ETag || response.Header.Get("X-File-Revision-ID") != accepted.File.ID {
		t.Fatal("DAV did not read the discovered immutable revision")
	}
	readerHeaders["If-None-Match"] = etag
	exchangeAPIRequest(t, server, "GET", fileURL, nil, readerHeaders, nil, 304)
	delete(readerHeaders, "If-None-Match")
	readerHeaders["Range"], readerHeaders["If-Range"] = "bytes=9-", etag
	_, body = exchangeAPIRequest(t, server, "GET", fileURL, nil, readerHeaders, nil, 206)
	if !bytes.Equal(body, data[9:]) {
		t.Fatal("DAV range differs from exact custody bytes")
	}
	delete(readerHeaders, "Range")
	delete(readerHeaders, "If-Range")
	response, _ = exchangeAPIRequest(t, server, "OPTIONS", dav, nil, readerHeaders, nil, 204)
	if response.Header.Get("Allow") != davReadMethods || response.Header.Get("DAV") != "" {
		t.Fatal("partial DAV profile advertised unimplemented compliance or methods")
	}
	for _, method := range []string{"DELETE", "COPY", "MOVE", "MKCOL", "PROPPATCH", "LOCK", "UNLOCK"} {
		exchangeAPIRequest(t, server, method, fileURL, nil, readerHeaders, []byte("untrusted write"), 405)
	}
	readerHeaders["Depth"] = "infinity"
	_, raw = exchangeAPIRequest(t, server, "PROPFIND", dav, nil, readerHeaders, nil, 403)
	if !bytes.Contains(raw, []byte("propfind-finite-depth")) {
		t.Fatal("infinite discovery did not return the DAV finite-depth refusal")
	}
	readerHeaders["Depth"] = "0"
	exchangeAPIRequest(t, server, "PROPFIND", dav, nil, readerHeaders, []byte(`<!DOCTYPE x><propfind xmlns="DAV:"><allprop/></propfind>`), 400)
	// Exact path modes apply to metadata as well as bytes, even when this
	// credential can read other files in the same partner's namespace.
	_, raw = exchangeAPIRequest(t, server, "GET", prefix+"/namespace/stat?path="+url.QueryEscape(virtual), nil, auth, nil, 200)
	var entry store.PathEntry
	if json.Unmarshal(raw, &entry) != nil {
		t.Fatal("source namespace revision missing")
	}
	mode := uint32(0600)
	commandHeaders["Idempotency-Key"] = "dav-owner-only"
	exchangeAPIRequest(t, server, "POST", prefix+"/namespace/commands", nil, commandHeaders, exchangeAPIJSON(t, store.PathCommand{Operation: "setstat", Path: virtual, ExpectedRevision: &entry.Revision, Mode: &mode}), 200)
	readerHeaders["Depth"] = "1"
	_, raw = exchangeAPIRequest(t, server, "PROPFIND", dav, nil, readerHeaders, nil, 207)
	if bytes.Contains(raw, []byte(accepted.File.ID)) || bytes.Contains(raw, []byte("a%20")) {
		t.Fatal("DAV metadata disclosed an unreadable child")
	}
	response, _ = exchangeAPIRequest(t, server, "GET", fileURL, nil, readerHeaders, nil, 403)
	if response.Header.Get("ETag") != "" {
		t.Fatal("unreadable path retained an immutable validator")
	}
	// Controlled intake acceptance stays held; it never becomes a DAV child.
	checking := &checks.Service{Custody: service}
	if _, err := checking.Register(t.Context(), scope, "dav-intake", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	held := []byte("record\nheld artifact\n")
	headers["Idempotency-Key"] = "dav-held"
	headers["X-File-Size"] = strconv.Itoa(len(held))
	headers["X-Content-SHA256"] = secure.Digest(held)
	exchangeAPIRequest(t, server, "PUT", prefix+"/namespace/file?path=/folder/held.csv", nil, headers, held, 201)
	_, raw = exchangeAPIRequest(t, server, "PROPFIND", dav, nil, auth, nil, 403) // Missing Depth means infinity.
	if !bytes.Contains(raw, []byte("propfind-finite-depth")) {
		t.Fatal("omitted depth silently recursed")
	}
	auth["Depth"] = "1"
	_, raw = exchangeAPIRequest(t, server, "PROPFIND", dav, nil, auth, nil, 207)
	if bytes.Contains(raw, []byte("held.csv")) {
		t.Fatal("held intake was published through DAV")
	}
	exchangeAPIRequest(t, server, "GET", dav+"held.csv", nil, auth, nil, 404)
	wrongScope := strings.Replace(dav, scope.Partner, secure.NewID(), 1)
	exchangeAPIRequest(t, server, "PROPFIND", wrongScope, nil, readerHeaders, nil, 401)
	exchangeAPIRequest(t, server, "POST", prefix+"/accounts/commands", cookie, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": "dav-revoke"}, exchangeAPIJSON(t, store.AccountCommand{Operation: "revoke", ID: actor.Actor, ExpectedRevision: 1}), 200)
	readerHeaders["If-None-Match"] = etag
	response, _ = exchangeAPIRequest(t, server, "HEAD", fileURL, nil, readerHeaders, nil, 401)
	if response.Header.Get("ETag") != "" {
		t.Fatal("stale DAV validator bypassed credential revocation")
	}
	tx, err := service.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var intents, runs int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`).Scan(&intents, &runs); err != nil || intents != 0 || runs != 0 {
		t.Fatal("DAV reads or untrusted properties granted forwarding or execution", err)
	}
}
