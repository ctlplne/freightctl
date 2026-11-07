//go:build integration

package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

// An actual small loopback TLS peer and native Node HTTPS client. This starts
// no Chrome,PostgreSQL,scanner or model and is not served-browser qualification.
func TestBrowserPinnedCommandUsesExactFixtureCAAndOrdinaryRequest(t *testing.T) {
	body := []byte(`{"definition_hash":"` + strings.Repeat("a", 64) + `","expected_revision":1}`)
	var contacts atomic.Int32
	var origin string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacts.Add(1)
		got, err := io.ReadAll(io.LimitReader(r.Body, 32769))
		if err != nil || r.Method != "POST" || r.URL.Path != "/exact-command" || !bytes.Equal(got, body) || r.Header.Get("Cookie") != "session=synthetic-private-cookie" || r.Header.Get("X-CSRF-Token") != "synthetic-private-csrf" || r.Header.Get("Idempotency-Key") != "synthetic-stored-command" || r.Header.Get("Origin") != origin || r.Header.Get("Authorization") != "" {
			t.Error("ordinary request identity,key,CSRF,scope or exact bytes changed")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	origin = server.URL
	defer server.Close()
	helper, err := filepath.Abs("../../scripts/browser-pinned-https.mjs")
	if err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(map[string]any{"helper": helper, "url": server.URL + "/exact-command", "origin": server.URL, "certificate": base64.StdEncoding.EncodeToString(server.Certificate().Raw), "body": base64.StdEncoding.EncodeToString(body)})
	script := `import {readFileSync} from 'node:fs';import {pathToFileURL} from 'node:url';
const c=JSON.parse(readFileSync(0,'utf8'));
const {fetchPinnedBrowserRequest}=await import(pathToFileURL(c.helper).href);
const original={url:()=>c.url,method:()=>"POST",postDataBuffer:()=>Buffer.from(c.body,'base64'),allHeaders:async()=>({"content-type":"application/json","cookie":"session=synthetic-private-cookie","x-csrf-token":"synthetic-private-csrf","idempotency-key":"synthetic-stored-command","origin":c.origin,"authorization":"synthetic-header-must-not-be-forwarded"})};
try{const r=await fetchPinnedBrowserRequest(original,c.origin,Buffer.from(c.certificate,'base64'));if(r.status!==201||r.body.toString()!=='{"accepted":true}')throw new Error('exact receipt changed');console.log('passed');}
catch(e){console.log(JSON.stringify({state:'failed',tls:/certificate|self.signed/i.test(String(e?.message))}));process.exitCode=1;}`
	command := exec.CommandContext(t.Context(), "node", "--input-type=module", "--eval", script)
	command.Stdin = bytes.NewReader(config)
	output, runErr := command.CombinedOutput()
	if runErr != nil || string(output) != "passed\n" || contacts.Load() != 1 {
		t.Fatalf("actual pinned browser command unavailable;failed=%t;TLS refusal=%t;contacts=%d;private output SHA256=%s", runErr != nil, bytes.Contains(output, []byte(`"tls":true`)), contacts.Load(), secure.Digest(output))
	}
}

func TestBrowserPinnedCommandRefusesChangedScopeCredentialsAndOversizedBody(t *testing.T) {
	var contacts atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacts.Add(1)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	helper, err := filepath.Abs("../../scripts/browser-pinned-https.mjs")
	if err != nil {
		t.Fatal(err)
	}
	wrongCertificate, wrongKey := filepath.Join(t.TempDir(), "wrong.crt"), filepath.Join(t.TempDir(), "wrong.key")
	if err = secure.DevCertificate(wrongCertificate, wrongKey); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(wrongCertificate)
	if err != nil {
		t.Fatal(err)
	}
	block, remaining := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(remaining)) != 0 {
		t.Fatal("independent wrong-CA fixture unavailable")
	}
	config, _ := json.Marshal(map[string]any{"helper": helper, "url": server.URL + "/exact-command", "origin": server.URL, "certificate": base64.StdEncoding.EncodeToString(server.Certificate().Raw), "wrong_certificate": base64.StdEncoding.EncodeToString(block.Bytes)})
	script := `import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import {pathToFileURL} from 'node:url';
const c=JSON.parse(readFileSync(0,'utf8'));const {fetchPinnedBrowserRequest,guardBrowserCommandRoute}=await import(pathToFileURL(c.helper).href);
const cert=Buffer.from(c.certificate,'base64'),base=()=>({url:()=>c.url,method:()=>"POST",postDataBuffer:()=>Buffer.from('{}'),allHeaders:async()=>({"content-type":"application/json","cookie":"session=synthetic-private-cookie","x-csrf-token":"synthetic-private-csrf","idempotency-key":"synthetic-stored-command","origin":c.origin})});
for(const mutate of [r=>r.method=()=>"GET",r=>r.postDataBuffer=()=>Buffer.alloc(32769),r=>r.url=()=>c.url.replace('https://','https://synthetic-user:synthetic-password@'),r=>r.url=()=>c.url+'#unapproved',r=>r.allHeaders=async()=>({}),r=>r.allHeaders=async()=>({...await base().allHeaders(),origin:'https://127.0.0.1:1'})]){
const r=base();mutate(r);await assert.rejects(()=>fetchPinnedBrowserRequest(r,c.origin,cert));}
await assert.rejects(()=>fetchPinnedBrowserRequest(base(),'https://127.0.0.1:1',cert));
await assert.rejects(()=>fetchPinnedBrowserRequest(base(),c.origin,Buffer.from('not a certificate')));
await assert.rejects(()=>fetchPinnedBrowserRequest(base(),c.origin,Buffer.from(c.wrong_certificate,'base64')));
let first,aborts=0;const original=new Error('synthetic first handler failure');
const guarded=guardBrowserCommandRoute(async()=>{throw original;},e=>{first??=e;});
await guarded({abort:async()=>{aborts++;}});await guarded({abort:async()=>{aborts++;throw new Error('secondary abort failure');}});
assert.equal(first,original);assert.equal(aborts,2);console.log('refused');`
	command := exec.CommandContext(t.Context(), "node", "--input-type=module", "--eval", script)
	command.Stdin = bytes.NewReader(config)
	output, runErr := command.CombinedOutput()
	if runErr != nil || string(output) != "refused\n" || contacts.Load() != 0 {
		t.Fatalf("pinned command scope/credential/handler refusal failed;failed=%t;HTTP contacts=%d;private output SHA256=%s", runErr != nil, contacts.Load(), secure.Digest(output))
	}
}
