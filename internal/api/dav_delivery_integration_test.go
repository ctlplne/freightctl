//go:build integration && davpeer

package api

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/protectedfs"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestDAVDeliveryNativeStockReceiverCLIIndependentApprovalAndExactBytes(t *testing.T) {
	peer := loadNativeDAVStockPeer(t)
	data := bytes.Repeat([]byte("independent DAV delivery;receipt is not business acceptance\n"), 2000)
	destination, receiverRoot := startNativeDAVBasicPeer(t, peer, []byte("readiness"), []byte("ready"), true)
	consumer, scope, token, server := browserAPI(t, 10*time.Minute)
	storage := filepath.Join(t.TempDir(), "delivery-custody")
	disk, err := custody.Open(storage)
	if err != nil {
		t.Fatal(err)
	}
	if err = consumer.Disk.Close(); err != nil {
		t.Fatal(err)
	}
	consumer.Disk = disk
	t.Cleanup(func() { disk.Close() })
	file, _, err := consumer.Accept(t.Context(), scope, "dav-source-custody", int64(len(data)), secure.Digest(data), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(peer.PrivateDirectory, "delivery-cli")
	if err = os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	writeRef := func(name string, value []byte) string {
		t.Helper()
		p := filepath.Join(private, name)
		f, e := protectedfs.CreateExclusive(p)
		if e != nil {
			t.Fatal("native fixture reference creation failed")
		}
		_, e = f.Write(value)
		syncErr, closeErr := f.Sync(), f.Close()
		if e != nil || syncErr != nil || closeErr != nil {
			t.Fatal("native fixture reference persistence failed")
		}
		return p
	}
	dsnBytes := []byte(consumer.DB.Pool.Config().ConnConfig.ConnString())
	dsnRef := writeRef("runtime.dsn", dsnBytes)
	secure.Clear(dsnBytes)
	tokenRef := writeRef("owner.token", token.Bytes)
	root := filepath.Dir(filepath.Dir(peer.PrivateDirectory))
	binary := filepath.Join(root, ".private", "freightctl-dav-delivery-native")
	info, err := buildinfo.ReadFile(binary)
	if err != nil || info.GoVersion != "go1.27.3" || info.Path != "github.com/ctlplne/freightctl/cmd/freightctl" {
		t.Fatal("actual native CLI build information differs")
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != runtime.GOARCH || settings["vcs.revision"] != peer.Commit || settings["vcs.modified"] != "false" {
		t.Fatal("CLI candidate or native architecture differs")
	}
	cliFile, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := secure.NewDigest()
	_, err = io.Copy(digest, cliFile)
	cliFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	cliHash := fmt.Sprintf("%x", digest.Sum(nil))
	sequence := 0
	cli := func(command string, extra ...string) []byte {
		t.Helper()
		sequence++
		p := filepath.Join(private, fmt.Sprintf("command-%03d.log", sequence))
		out, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		args := []string{command, "-dsn-file", dsnRef, "-token-file", tokenRef, "-tenant", scope.Tenant, "-partner", scope.Partner, "-storage", storage, "-max-file-bytes", "8388608", "-max-stored-bytes", "67108864"}
		args = append(args, extra...)
		child := exec.CommandContext(t.Context(), binary, args...)
		child.Env = davApplicationEnvironment(os.Environ())
		child.Dir = root
		child.Stdout, child.Stderr = out, out
		e = child.Run()
		syncErr, closeErr := out.Sync(), out.Close()
		raw, readErr := os.ReadFile(p)
		if e != nil || syncErr != nil || closeErr != nil || readErr != nil || len(raw) > 64<<10 {
			t.Fatalf("native CLI failed;closed-output-SHA256=%s;command=%s", secure.Digest(raw), command)
		}
		t.Logf("native CLI command=%s;closed-output-SHA256=%s;binary-SHA256=%s;candidate=%s", command, secure.Digest(raw), cliHash, peer.Commit)
		return raw
	}
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	cookie, csrf := loginBrowser(t, server, scope, token)
	reviewerToken, reviewer := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"inspect", "workflow_approve"})
	ownerHeaders := map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": "dav-policy"}
	exchangeAPIRequest(t, server, "POST", prefix+"/outbound-dispatch-policy", nil, ownerHeaders, exchangeAPIJSON(t, delivery.DispatchPolicyChange{Mode: "independent"}), 200)
	definition := delivery.DAVDefinition{Destination: destination, StagingDirectory: "/dav/stage", ReceiverContract: store.DAVReceiverContract{Schema: 1, DocumentSHA256: secure.Digest([]byte("native fixture contract:private stage,exclusive PUT,source ETag nonoverwrite MOVE,delivery-ID deduplication,exact readback;not enterprise qualification")), StagingVisibility: "receiver-private", Put: "exclusive-create", Move: "source-etag-no-overwrite", Duplicates: "receiver-deduplicates-delivery-id", Receipt: "exact-readback"}}
	request := delivery.Request{FileID: file.ID, Directory: "/dav/inbox", Filename: "input.dat", DAV: &definition}
	requestRef := writeRef("request.json", exchangeAPIJSON(t, request))
	createdRaw := cli("delivery-create", "-request-file", requestRef, "-idempotency-key", "dav-create")
	var created delivery.Result
	if json.Unmarshal(createdRaw, &created) != nil || created.Delivery == nil || created.Replayed {
		t.Fatal("native CLI draft response invalid")
	}
	d := created.Delivery
	engine := &delivery.Service{Custody: consumer}
	if _, err = engine.Work(t.Context(), scope, d.ID); err != store.ErrDispatchApproval {
		t.Fatal("independent dispatch approval did not block sending")
	}
	if entries, err := os.ReadDir(filepath.Join(receiverRoot, "stage")); err != nil || len(entries) != 0 {
		t.Fatal("unapproved delivery wrote stage bytes")
	}
	selection := delivery.DispatchSelection{DeliveryID: d.ID, DispatchDecision: delivery.DispatchDecision{Hash: d.DefinitionHash, Revision: d.Revision}, ReviewerID: reviewer.Actor}
	_, previewRaw := exchangeAPIRequest(t, server, "POST", prefix+"/outbound-dispatch-reviews/preview", nil, ownerHeaders, exchangeAPIJSON(t, selection), 200)
	var preview delivery.DispatchPreview
	if json.Unmarshal(previewRaw, &preview) != nil || preview.Definition.Schema != 3 || preview.ExternalContact || preview.GrantsFileAccess || preview.Definition.Effect.DAV == nil {
		t.Fatal("native API reviewed meaning invalid")
	}
	ownerHeaders["Idempotency-Key"] = "dav-propose"
	_, proposedRaw := exchangeAPIRequest(t, server, "POST", prefix+"/outbound-dispatch-reviews", nil, ownerHeaders, exchangeAPIJSON(t, delivery.DispatchProposal{Selection: selection, Hash: preview.Hash}), 200)
	var proposed delivery.DispatchResult
	var review delivery.DispatchReviewResult
	if json.Unmarshal(proposedRaw, &proposed) != nil || json.Unmarshal(proposed.Resource, &review) != nil || !store.ValidID(review.Review.ID) {
		t.Fatal("native API review proposal invalid")
	}
	reviewerHeaders := map[string]string{"Authorization": "Bearer " + string(reviewerToken.Bytes), "Idempotency-Key": "dav-independent-approve"}
	exchangeAPIRequest(t, server, "POST", prefix+"/outbound-dispatch-reviews/"+review.Review.ID+"/approve", nil, reviewerHeaders, exchangeAPIJSON(t, delivery.DispatchDecision{Hash: review.Review.Hash, Revision: review.Review.Revision}), 200)
	tx, err := consumer.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	var valid, equal bool
	expected, _ := json.Marshal(preview.Definition.Effect)
	err = tx.Tx.QueryRow(t.Context(), `SELECT freightctl_dav_delivery_definition(definition),freightctl_outbound_dispatch_expected_effect(d,'')=$2::jsonb FROM delivery_intents d WHERE delivery_id=$1`, d.ID, string(expected)).Scan(&valid, &equal)
	if err != nil || !valid || !equal {
		tx.Tx.Rollback(t.Context())
		t.Fatal("native SQL shape or reviewed effect differs")
	}
	for _, bad := range []string{`jsonb_set(definition,'{schema_version}','1')`, `jsonb_set(definition,'{dav,receiver_contract,move}','"may-replace"')`, `jsonb_set(definition,'{dav,staging_directory}','"/dav/inbox/visible"')`, `definition||'{"workflow_binding":{}}'::jsonb`, `definition||'{"ftps":{}}'::jsonb`} {
		if err = tx.Tx.QueryRow(t.Context(), `SELECT freightctl_dav_delivery_definition(`+bad+`) FROM delivery_intents WHERE delivery_id=$1`, d.ID).Scan(&valid); err != nil || valid {
			tx.Tx.Rollback(t.Context())
			t.Fatal("native SQL mixed or unsafe DAV contract admitted")
		}
	}
	tx.Tx.Rollback(t.Context())
	cli("delivery-approve", "-delivery-id", d.ID, "-definition-hash", d.DefinitionHash, "-expected-revision", strconv.FormatInt(d.Revision, 10), "-idempotency-key", "dav-queue")
	workedRaw := cli("delivery-work", "-delivery-id", d.ID)
	var worked store.Delivery
	if json.Unmarshal(workedRaw, &worked) != nil || worked.State != "succeeded" || worked.Attempts != 1 || worked.Fence != 1 {
		t.Fatal("native stock-server delivery did not retain one exact attempt/fence")
	}
	final := filepath.Join(receiverRoot, "inbox", d.ID+"-input.dat")
	got, err := os.ReadFile(final)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("independent stock receiver final bytes differ")
	}
	if entries, err := os.ReadDir(filepath.Join(receiverRoot, "stage")); err != nil || len(entries) != 0 {
		t.Fatal("stock MOVE left unexpected staging bytes")
	}
	var receipt map[string]any
	if json.Unmarshal(worked.Observation, &receipt) != nil || receipt["business_acceptance"] != "unknown" || receipt["file_fsync_acknowledged"] != false || receipt["move_acknowledged"] != true {
		t.Fatal("native receipt invented business/durability guarantees")
	}
	// These are explicit task-owned transport conformance probes,not product
	// sends or business effects. The happy product journey above independently
	// establishes that the same stock peer supports valid exclusive PUT/MOVE.
	probeRef := writeRef("protocol-probe-source", data)
	probeSource, err := os.Open(probeRef)
	if err != nil {
		t.Fatal(err)
	}
	defer probeSource.Close()
	for _, kind := range []string{"existing-stage", "changed-stage-etag", "existing-final"} {
		id := secure.NewID()
		stageName, finalName := ".freightctl-probe-"+id+".partial", "probe-"+id+".dat"
		stageDisk, finalDisk := filepath.Join(receiverRoot, "stage", stageName), filepath.Join(receiverRoot, "inbox", finalName)
		old := []byte("independently retained old receiver bytes")
		if kind == "existing-stage" {
			if err = os.WriteFile(stageDisk, old, 0600); err != nil {
				t.Fatal(err)
			}
		}
		transport, err := secure.NewDAVDeliveryClient(t.Context(), destination, "/dav/stage/"+stageName, "/dav/inbox/"+finalName, int64(len(data)), secure.Digest(data), func() error { return t.Context().Err() })
		if err != nil {
			t.Fatal(err)
		}
		if kind == "existing-stage" {
			if err = transport.PutStage(t.Context(), probeSource); err == nil {
				transport.Close()
				t.Fatal("stock peer overwrote an existing exclusive stage")
			}
			transport.Close()
			if got, err = os.ReadFile(stageDisk); err != nil || !bytes.Equal(got, old) {
				t.Fatal("stock peer changed old stage bytes")
			}
		} else {
			if err = transport.PutStage(t.Context(), probeSource); err != nil {
				transport.Close()
				t.Fatal("stock condition probe stage upload failed")
			}
			if err = transport.VerifyStage(t.Context()); err != nil {
				transport.Close()
				t.Fatal("stock condition probe exact stage verification failed")
			}
			if kind == "changed-stage-etag" {
				if err = os.WriteFile(stageDisk, old, 0600); err != nil {
					transport.Close()
					t.Fatal(err)
				}
			} else if err = os.WriteFile(finalDisk, old, 0600); err != nil {
				transport.Close()
				t.Fatal(err)
			}
			if err = transport.Publish(t.Context()); err == nil {
				transport.Close()
				t.Fatal("stock peer ignored stale source ETag or final non-overwrite")
			}
			transport.Close()
			if kind == "existing-final" {
				if got, err = os.ReadFile(finalDisk); err != nil || !bytes.Equal(got, old) {
					t.Fatal("stock peer replaced existing final bytes")
				}
				if got, err = os.ReadFile(stageDisk); err != nil || !bytes.Equal(got, data) {
					t.Fatal("refused final collision changed exact stage bytes")
				}
			} else if got, err = os.ReadFile(stageDisk); err != nil || !bytes.Equal(got, old) {
				t.Fatal("stale source condition moved or changed producer bytes")
			}
		}
		if kind != "existing-final" {
			if _, err = os.Stat(finalDisk); !os.IsNotExist(err) {
				t.Fatal("refused condition still published a final path")
			}
		}
	}
	if err = os.Remove(destination.PasswordFile); err != nil {
		t.Fatal(err)
	}
	replayRaw := cli("delivery-create", "-request-file", requestRef, "-idempotency-key", "dav-create")
	var replay delivery.Result
	if json.Unmarshal(replayRaw, &replay) != nil || !replay.Replayed || replay.Delivery.ID != d.ID {
		t.Fatal("original creation receipt changed after credential removal")
	}
	againRaw := cli("delivery-work", "-delivery-id", d.ID)
	var again store.Delivery
	var savedReceipt map[string]any
	if json.Unmarshal(againRaw, &again) != nil || json.Unmarshal(again.Observation, &savedReceipt) != nil || again.State != "succeeded" || again.Attempts != 1 || again.Fence != 1 || !reflect.DeepEqual(savedReceipt, receipt) {
		t.Fatal("completed delivery repeated effects or changed its receipt")
	}
	if got, err = os.ReadFile(final); err != nil || !bytes.Equal(got, data) {
		t.Fatal("receipt recovery changed independent final bytes")
	}
	t.Logf("native DAV delivery candidate=%s;arch=%s;CLI-SHA256=%s;peer-SHA256=%s;content-SHA256=%s;business-acceptance=unknown;enterprise-receiver-contract=owed", peer.Commit, runtime.GOARCH, cliHash, peer.BinarySHA256, secure.Digest(data))
}
