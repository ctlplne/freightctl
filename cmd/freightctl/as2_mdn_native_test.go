//go:build cmspeer

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestNativeAS2MDNVerification(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	runOpenSSL := func(args ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, "openssl", args...)
		command.Dir = dir
		if err := command.Run(); err != nil {
			t.Fatalf("independent OpenSSL %s failed: %v", args[0], err)
		}
	}
	writePrivate := func(name, contents string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	readFile := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	createSigner := func(name string) {
		t.Helper()
		runOpenSSL("req", "-new", "-newkey", "rsa:3072", "-noenc", "-x509", "-sha256", "-days", "1",
			"-subj", "/CN=freightctl-AS2-"+name, "-addext", "basicConstraints=critical,CA:FALSE",
			"-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=emailProtection",
			"-keyout", name+".key", "-out", name+".pem")
	}
	createSigner("peer")
	runOpenSSL("x509", "-in", "peer.pem", "-outform", "DER", "-out", "peer.der")
	cert := writePrivate("pinned.der", string(readFile("peer.der")))
	const messageID = "<freightctl-test@peer.example>"
	const original = "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\nabc\x00\r\n"
	writePrivate("original.mime", original)
	runOpenSSL("dgst", "-sha256", "-binary", "-out", "original-mic.bin", "original.mime")
	mic := base64.StdEncoding.EncodeToString(readFile("original-mic.bin"))
	const disposition = "automatic-action/MDN-sent-automatically; processed"
	report := strings.Join([]string{
		`Content-Type: multipart/report; report-type=disposition-notification; boundary="freightctl-mdn"`,
		"MIME-Version: 1.0", "", "--freightctl-mdn", "Content-Type: text/plain", "",
		"Received by the AS2 peer.", "--freightctl-mdn", "Content-Type: message/disposition-notification",
		"Content-Transfer-Encoding: 7bit", "", "Reporting-UA: peer", "Original-Recipient: rfc822; freightctl-peer",
		"Final-Recipient: rfc822; freightctl-peer", "Original-Message-ID: " + messageID,
		"Disposition: " + disposition, "Received-Content-MIC: " + mic + ", sha-256",
		"", "--freightctl-mdn--", "",
	}, "\r\n")
	signed := func(contents, algorithm string, extra ...string) (string, string) {
		t.Helper()
		path := writePrivate("report.mime", contents)
		args := []string{"cms", "-sign", "-binary", "-in", "report.mime", "-signer", "peer.pem",
			"-inkey", "peer.key", "-md", algorithm, "-outform", "DER", "-out", "generated.der"}
		runOpenSSL(append(args, extra...)...)
		return path, writePrivate("signature.der", string(readFile("generated.der")))
	}
	expectation := map[string]any{
		"schema_version": 1, "original_message_id": messageID, "final_recipient": "freightctl-peer",
		"content_mic_sha256": secure.Digest([]byte(original)), "signer_certificate_sha256": secure.Digest(readFile("peer.der")),
	}
	request := func() string {
		t.Helper()
		wire, err := json.Marshal(expectation)
		if err != nil {
			t.Fatal(err)
		}
		return writePrivate("request.json", string(wire))
	}
	arguments := func(path, signature string) []string {
		t.Helper()
		return []string{"--request-file", request(), "--report-file", path,
			"--signature-file", signature, "--signer-certificate-file", cert}
	}
	verify := func(path, signature string) (string, error) {
		t.Helper()
		output := new(bytes.Buffer)
		err := verifyAS2MDN(arguments(path, signature), output)
		return output.String(), err
	}

	path, signature := signed(report, "sha256")
	wire, err := verify(path, signature)
	var result struct {
		Disposition        string `json:"disposition"`
		ReportSHA256       string `json:"signed_report_sha256"`
		ContentMIC         string `json:"content_mic_sha256"`
		ReceiverDurability string `json:"receiver_durability"`
		BusinessAcceptance string `json:"business_acceptance"`
	}
	if err != nil || json.Unmarshal([]byte(wire), &result) != nil ||
		result.Disposition != "processed" || result.ReportSHA256 != secure.Digest([]byte(report)) ||
		result.ContentMIC != expectation["content_mic_sha256"] || result.ReceiverDurability != "unknown" || result.BusinessAcceptance != "unknown" ||
		strings.Contains(wire, messageID) || strings.Contains(wire, "freightctl-peer") {
		t.Fatalf("stock SHA-256 CMS receipt did not verify with the exact wire bindings: %v", err)
	}
	childArgs := append([]string{"-test.run=^TestAS2CommandProcess$", "--", "as2-mdn-verify"}, arguments(path, signature)...)
	if actual, err := exec.CommandContext(ctx, os.Args[0], childArgs...).Output(); err != nil || string(actual) != wire {
		t.Fatalf("native CLI command failed to produce the same verified receipt: %v", err)
	}
	if err := secure.VerifyAS2DetachedCMS([]byte(report), readFile("signature.der"), readFile("peer.der"),
		expectation["signer_certificate_sha256"].(string), time.Now().Add(48*time.Hour)); err == nil {
		t.Fatal("signed receipt survived expiration of the pinned certificate")
	}

	runOpenSSL("cms", "-sign", "-binary", "-crlfeol", "-in", "report.mime", "-signer", "peer.pem",
		"-inkey", "peer.key", "-md", "sha256", "-outform", "SMIME", "-out", "generated.mime")
	runOpenSSL("cms", "-cmsout", "-inform", "SMIME", "-in", "generated.mime", "-outform", "DER", "-out", "captured.der")
	capture := string(readFile("generated.mime"))
	capturedDER := string(readFile("captured.der"))
	wantCapture, err := verify(path, writePrivate("capture-signature.der", capturedDER))
	if err != nil {
		t.Fatalf("OpenSSL detached the captured signature from the original MIME bytes: %v", err)
	}
	captureArgs := func(receipt string) []string {
		t.Helper()
		return []string{"--request-file", request(), "--receipt-file", writePrivate("receipt.mime", receipt), "--signer-certificate-file", cert}
	}
	verifyCapture := func(receipt string) (string, error) {
		t.Helper()
		output := new(bytes.Buffer)
		err := verifyAS2MDN(captureArgs(receipt), output)
		return output.String(), err
	}
	childArgs = append([]string{"-test.run=^TestAS2CommandProcess$", "--", "as2-mdn-verify"}, captureArgs(capture)...)
	if actual, err := exec.CommandContext(ctx, os.Args[0], childArgs...).Output(); err != nil || string(actual) != wantCapture {
		t.Fatalf("native CLI changed the signed entity or result from the complete OpenSSL receipt: %v", err)
	}
	const binaryEnvelope = "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha256; boundary=freightctl-signed\r\n\r\n"
	const binaryFirst = "--freightctl-signed \t\r\n"
	const binarySecond = "\r\n--freightctl-signed\r\nContent-Type: application/pkcs7-signature\r\n"
	const binaryClose = "\r\n--freightctl-signed--\r\n"
	binaryCapture := binaryEnvelope + binaryFirst + report + binarySecond +
		"Content-Transfer-Encoding: binary\r\n\r\n" + capturedDER + binaryClose
	for _, accepted := range []string{
		binaryCapture,
		strings.Replace(binaryCapture, "Content-Transfer-Encoding: binary\r\n", "", 1),
		capture + "\r\nUnsigned epilogue\r\n",
	} {
		if out, err := verifyCapture(accepted); err != nil || out != wantCapture {
			t.Fatalf("MIME framing changed the verified report or signature bytes: %v", err)
		}
	}
	_, signatureWire, found := strings.Cut(capture, "\r\nContent-Type: application/pkcs7-signature")
	if !found {
		t.Fatal("stock OpenSSL omitted its signature part")
	}
	_, encodedSignature, found := strings.Cut(signatureWire, "\r\n\r\n")
	if !found || encodedSignature == "" {
		t.Fatal("stock OpenSSL omitted its base64 signature body")
	}
	encodedStart := len(capture) - len(encodedSignature)
	for index, changed := range []string{
		strings.Replace(capture, "Received by the AS2 peer.", "Rejected by the AS2 peer.", 1),
		strings.Replace(capture, report, strings.TrimSuffix(report, "\r\n"), 1),
		strings.Replace(capture, `micalg="sha-256"`, `micalg="sha-512"`, 1),
		strings.Replace(capture, `protocol="application/pkcs7-signature"`, `protocol="application/x-pkcs7-signature"`, 1),
		strings.Replace(capture, "Content-Transfer-Encoding: base64", "Content-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: binary", 1),
		capture[:encodedStart] + "!" + encodedSignature,
		capture[:encodedStart] + "\r" + encodedSignature,
		"Content-Type: text/plain\r\n" + capture,
		strings.TrimSuffix(binaryCapture, binaryClose),
		strings.TrimSuffix(binaryCapture, binaryClose) + "\r\n--freightctl-signed\r\n\r\nextra" + binaryClose,
		capture + strings.Repeat(" ", 128<<10),
	} {
		if changed == capture {
			t.Fatalf("receipt fixture %d changed no bytes", index)
		}
		if out, err := verifyCapture(changed); err == nil || out != "" {
			t.Fatalf("ambiguous, unsupported or changed signed capture %d produced evidence", index)
		}
	}
	if output := new(bytes.Buffer); verifyAS2MDN(append(captureArgs(capture), "--report-file", path, "--signature-file", signature), output) == nil || output.Len() != 0 {
		t.Fatal("the CLI accepted competing sources for the signed receipt")
	}
	t.Log("stock OpenSSL complete MIME receipt matched its detached report and signature")

	refused := func(path, signature string) {
		t.Helper()
		if out, err := verify(path, signature); err == nil || out != "" {
			t.Fatal("untrusted report produced verified receipt output")
		}
	}
	refused(writePrivate("changed.mime", strings.Replace(report, "Received by", "Refused by", 1)), signature)
	createSigner("other")
	runOpenSSL("cms", "-sign", "-binary", "-in", "report.mime", "-signer", "other.pem",
		"-inkey", "other.key", "-md", "sha256", "-outform", "DER", "-out", "other.der")
	refused(path, writePrivate("other-signature.der", string(readFile("other.der"))))
	expectation["signer_certificate_sha256"] = secure.Digest([]byte("unrelated pin"))
	refused(path, signature)
	expectation["signer_certificate_sha256"] = secure.Digest(readFile("peer.der"))
	expectation["content_mic_sha256"] = secure.Digest([]byte("different original content"))
	refused(path, signature)
	expectation["content_mic_sha256"] = secure.Digest([]byte(original))
	expectation["original_message_id"] = "<wrong@peer.example>"
	refused(path, signature)
	expectation["original_message_id"] = messageID
	expectation["final_recipient"] = "different-recipient"
	refused(path, signature)
	expectation["final_recipient"] = "freightctl-peer"
	for _, contents := range []string{
		strings.Replace(report, disposition, disposition+"/warning: duplicate-document", 1),
		strings.Replace(report, disposition, disposition+"/error: authentication-failed", 1),
		strings.Replace(report, disposition, "automatic-action/MDN-sent-automatically; failed", 1),
		strings.Replace(report, "Received-Content-MIC: ", "Error: upstream refused\r\nReceived-Content-MIC: ", 1),
		strings.Replace(report, "Received-Content-MIC: ", "Original-Message-ID: "+messageID+"\r\nReceived-Content-MIC: ", 1),
		strings.Replace(report, ", sha-256", ", sha-1", 1),
		strings.ReplaceAll(report, "\r\n", "\n"),
	} {
		path, signature = signed(contents, "sha256")
		refused(path, signature)
	}
	path, signature = signed(report, "sha512")
	refused(path, signature)
	path, signature = signed(report, "sha256", "-nodetach")
	refused(path, signature)
	path, signature = signed(report, "sha256", "-noattr")
	refused(path, signature)
	path, signature = signed(report, "sha256", "-nocerts")
	refused(path, signature)

	const dispositionProfile = "as2-signed-disposition-sha256-v1"
	type observedDisposition struct {
		Profile            string `json:"profile"`
		Disposition        string `json:"disposition"`
		MICStatus          string `json:"content_mic_status"`
		MIC                string `json:"content_mic_sha256"`
		ErrorCode          string `json:"error_code"`
		ReceiverDurability string `json:"receiver_durability"`
		BusinessAcceptance string `json:"business_acceptance"`
	}
	noMIC := strings.Replace(report, "Received-Content-MIC: "+mic+", sha-256\r\n", "", 1)
	warning := strings.Replace(report, disposition, disposition+"/warning: peer-private note", 1)
	processingError := strings.Replace(noMIC, disposition, disposition+"/error: decryption-failed", 1)
	failed := strings.Replace(noMIC, disposition, "manual-action/MDN-sent-manually; failed/failure: private rejection", 1)
	for _, tc := range []struct {
		report, disposition, micStatus, errorCode string
	}{
		{report, "processed", "matched", ""},
		{warning, "processed/warning", "matched", ""},
		{processingError, "processed/error", "absent", "decryption-failed"},
		{failed, "failed", "absent", ""},
	} {
		path, signature = signed(tc.report, "sha256")
		out := new(bytes.Buffer)
		err := verifyAS2MDN(append(arguments(path, signature), "--receipt-profile", dispositionProfile), out)
		var observed observedDisposition
		if err != nil || json.Unmarshal(out.Bytes(), &observed) != nil ||
			observed.Profile != dispositionProfile || observed.Disposition != tc.disposition ||
			observed.MICStatus != tc.micStatus || observed.ErrorCode != tc.errorCode ||
			observed.ReceiverDurability != "unknown" || observed.BusinessAcceptance != "unknown" {
			t.Fatalf("signed disposition %s did not produce the bounded peer result: %v", tc.disposition, err)
		}
		if tc.micStatus == "matched" && observed.MIC != expectation["content_mic_sha256"] ||
			tc.micStatus == "absent" && observed.MIC != "" ||
			strings.Contains(out.String(), "peer-private") || strings.Contains(out.String(), "private rejection") {
			t.Fatal("signed disposition overstated integrity or disclosed the free-text peer note")
		}
	}
	for _, changed := range []string{
		noMIC,
		strings.Replace(warning, mic, base64.StdEncoding.EncodeToString(make([]byte, 32)), 1),
		strings.Replace(processingError, messageID, "<changed@peer.example>", 1),
		strings.Replace(processingError, "Disposition: ", "Warning: contradiction\r\nDisposition: ", 1),
		strings.Replace(processingError, "/error: decryption-failed", "/unknown: peer-private note", 1),
	} {
		path, signature = signed(changed, "sha256")
		output := new(bytes.Buffer)
		if err := verifyAS2MDN(append(arguments(path, signature), "--receipt-profile", dispositionProfile), output); err == nil || output.Len() != 0 {
			t.Fatal("invalid or inconsistent signed disposition produced an observation")
		}
	}
	signed(processingError, "sha256")
	runOpenSSL("cms", "-sign", "-binary", "-crlfeol", "-in", "report.mime", "-signer", "peer.pem",
		"-inkey", "peer.key", "-md", "sha256", "-outform", "SMIME", "-out", "negative.mime")
	cmd := append([]string{"-test.run=^TestAS2CommandProcess$", "--", "as2-mdn-verify"},
		captureArgs(string(readFile("negative.mime")))...)
	cmd = append(cmd, "--receipt-profile", dispositionProfile)
	out, err := exec.CommandContext(ctx, os.Args[0], cmd...).Output()
	var observed observedDisposition
	if err != nil || json.Unmarshal(out, &observed) != nil || observed.Disposition != "processed/error" ||
		observed.MICStatus != "absent" || observed.ErrorCode != "decryption-failed" {
		t.Fatalf("CLI full signed capture failed to observe the authenticated error: %v", err)
	}
	t.Log("signed AS2 warnings and failures retained their disposition without upgrading acceptance")
}

func TestAS2CommandProcess(t *testing.T) {
	index := slices.Index(os.Args, "--")
	if index < 0 || index+1 >= len(os.Args) {
		return
	}
	switch os.Args[index+1] {
	case "as2-mdn-verify", "as2-message-open", "as2-message-seal":
	default:
		return
	}
	if err := run(os.Args[index+1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}
