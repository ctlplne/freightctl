package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDAVCollectionMoveAcceptsOnlyExactNamespaceConditionAndFullDepth(t *testing.T) {
	const base = "/v1/tenants/t/partners/p/dav/"
	request := func() *http.Request {
		r := httptest.NewRequest("MOVE", "https://localhost"+base+"source/", nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("X-Freightctl-Namespace-Revision", "10000000-1111-4111-8111-111111111111:1")
		r.Header.Set("Idempotency-Key", "collection-move-original")
		r.Header.Set("Overwrite", "F")
		r.Header.Set("Destination", "https://localhost"+base+"target/")
		r.Header.Set("Depth", "infinity")
		return r
	}
	r := request()
	w := httptest.NewRecorder()
	if !prepareDAVRequest(w, r) {
		t.Fatalf("exact complete collection move refused before service;status=%d", w.Code)
	}
	r = request()
	r.Header.Del("Depth")
	w = httptest.NewRecorder()
	if !prepareDAVRequest(w, r) {
		t.Fatal("absent collection depth did not retain full-tree semantics", w.Code)
	}
	for _, change := range []struct {
		name   string
		apply  func(*http.Request)
		status int
	}{
		{"missing condition", func(r *http.Request) { r.Header.Del("X-Freightctl-Namespace-Revision") }, 428},
		{"ambiguous condition", func(r *http.Request) {
			r.Header.Add("X-Freightctl-Namespace-Revision", "10000000-1111-4111-8111-111111111111:2")
		}, 400},
		{"finite depth", func(r *http.Request) { r.Header.Set("Depth", "1") }, 400},
		{"byte condition", func(r *http.Request) { r.Header.Set("If-Match", `"unrelated-byte-tag"`) }, 400},
		{"overwrite", func(r *http.Request) { r.Header.Set("Overwrite", "T") }, 428},
		{"foreign host", func(r *http.Request) { r.Header.Set("Destination", "https://elsewhere.invalid"+base+"target/") }, 400},
		{"file destination", func(r *http.Request) { r.Header.Set("Destination", base+"target") }, 400},
		{"missing key", func(r *http.Request) { r.Header.Del("Idempotency-Key") }, 400},
	} {
		t.Run(change.name, func(t *testing.T) {
			r := request()
			change.apply(r)
			w := httptest.NewRecorder()
			if prepareDAVRequest(w, r) || w.Code != change.status {
				t.Fatal("collection mutation escaped its declared contract", w.Code)
			}
		})
	}
}

func TestDAVMoveDestinationEncodedHashRemainsALiteralNamespaceName(t *testing.T) {
	const base = "/v1/tenants/t/partners/p/dav/"
	for _, collection := range []bool{false, true} {
		r := httptest.NewRequest("MOVE", "https://localhost"+base+"source", nil)
		value := "https://localhost" + base + "literal%23name"
		if collection {
			value += "/"
		}
		r.Header.Set("Destination", value)
		var target string
		var err error
		if collection {
			target, err = davCollectionDestination(r, base)
		} else {
			target, err = davMoveDestination(r, base)
		}
		if err != nil || target != "/literal#name" {
			t.Fatal("encoded filename character became a forbidden URI fragment", err)
		}
	}
}

func TestDAVMoveDestinationsRejectEvenEmptyURIFragments(t *testing.T) {
	const base = "/v1/tenants/t/partners/p/dav/"
	for _, collection := range []bool{false, true} {
		r := httptest.NewRequest("MOVE", "https://localhost"+base+"source", nil)
		target := "https://localhost" + base + "target"
		if collection {
			target += "/"
		}
		r.Header.Set("Destination", target+"#")
		var err error
		if collection {
			_, err = davCollectionDestination(r, base)
		} else {
			_, err = davMoveDestination(r, base)
		}
		if err == nil {
			t.Fatal("empty URI fragment silently became another namespace instruction")
		}
	}
}
