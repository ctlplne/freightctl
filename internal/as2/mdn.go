package as2

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

const (
	VerificationProfile = "as2-detached-positive-mdn-sha256-v1"
	DispositionProfile  = "as2-signed-disposition-sha256-v1"
)

var ErrMDN = errors.New("AS2 MDN is outside the selected receipt profile or differs from the original message")

// ExpectedMDN comes from the sender's original message record. The MIC is
// the hash of the original signed MIME entity, including its MIME headers.
type ExpectedMDN struct {
	Schema            int    `json:"schema_version"`
	OriginalMessageID string `json:"original_message_id"`
	FinalRecipient    string `json:"final_recipient"`
	ContentMIC        string `json:"content_mic_sha256"`
	SignerPin         string `json:"signer_certificate_sha256"`
}

type VerifiedMDN struct {
	Profile            string `json:"profile"`
	Disposition        string `json:"disposition"`
	MessageIDSHA256    string `json:"original_message_id_sha256"`
	ContentMIC         string `json:"content_mic_sha256,omitempty"`
	ContentMICStatus   string `json:"content_mic_status,omitempty"`
	ErrorCode          string `json:"error_code,omitempty"`
	SignerSHA256       string `json:"signer_certificate_sha256"`
	ReportSHA256       string `json:"signed_report_sha256"`
	SignatureSHA256    string `json:"signature_sha256"`
	ReceiverDurability string `json:"receiver_durability"`
	BusinessAcceptance string `json:"business_acceptance"`
}

func ValidMDNProfile(profile string) bool {
	return profile == VerificationProfile || profile == DispositionProfile
}

func VerifyMDN(profile string, expected ExpectedMDN, report, signature, certificate []byte, now time.Time) (VerifiedMDN, error) {
	if !ValidMDNProfile(profile) || expected.Schema != 1 || !visibleASCII(expected.OriginalMessageID, 998) ||
		!visibleASCII(expected.FinalRecipient, 128) || !lowerHexSHA256(expected.ContentMIC) || !lowerHexSHA256(expected.SignerPin) ||
		len(report) > secure.MaxAS2SignedReport {
		return VerifiedMDN{}, ErrMDN
	}
	if err := secure.VerifyAS2DetachedCMS(report, signature, certificate, expected.SignerPin, now); err != nil {
		return VerifiedMDN{}, err
	}
	fields, err := receiptFields(report)
	if err != nil || one(fields, "Original-Message-Id") != expected.OriginalMessageID ||
		!matchesRecipient(one(fields, "Final-Recipient"), expected.FinalRecipient) {
		return VerifiedMDN{}, ErrMDN
	}
	if original := fields.Values("Original-Recipient"); len(original) != 0 &&
		(len(original) != 1 || !matchesRecipient(original[0], expected.FinalRecipient)) {
		return VerifiedMDN{}, ErrMDN
	}
	disposition, errorCode := reportedDisposition(fields, profile)
	if disposition == "" {
		return VerifiedMDN{}, ErrMDN
	}
	mic, err := observedMIC(fields.Values("Received-Content-Mic"), expected.ContentMIC, disposition == "processed")
	if err != nil {
		return VerifiedMDN{}, err
	}
	var status string
	if profile == DispositionProfile {
		status = "absent"
		if mic != "" {
			status = "matched"
		}
	}
	return VerifiedMDN{
		Profile: profile, Disposition: disposition, MessageIDSHA256: secure.Digest([]byte(expected.OriginalMessageID)),
		ContentMIC: mic, ContentMICStatus: status, ErrorCode: errorCode,
		SignerSHA256: expected.SignerPin, ReportSHA256: secure.Digest(report), SignatureSHA256: secure.Digest(signature),
		ReceiverDurability: "unknown", BusinessAcceptance: "unknown",
	}, nil
}

func observedMIC(values []string, expected string, required bool) (string, error) {
	if len(values) == 0 && !required {
		return "", nil
	}
	if len(values) != 1 {
		return "", ErrMDN
	}
	value, algorithm, found := strings.Cut(values[0], ",")
	if !found || !sha256MICAlgorithm(algorithm) {
		return "", ErrMDN
	}
	mic, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(value))
	if err != nil || len(mic) != 32 || hex.EncodeToString(mic) != expected {
		return "", ErrMDN
	}
	return expected, nil
}

func reportedDisposition(fields textproto.MIMEHeader, profile string) (disposition, errorCode string) {
	mode, value, found := strings.Cut(one(fields, "Disposition"), ";")
	if !found {
		return "", ""
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	const automatic = "automatic-action/mdn-sent-automatically"
	switch mode {
	case automatic:
	case "automatic-action/mdn-sent-manually", "manual-action/mdn-sent-automatically", "manual-action/mdn-sent-manually":
		if profile != DispositionProfile {
			return "", ""
		}
	default:
		return "", ""
	}
	name, annotation, annotated := strings.Cut(value, ":")
	name = strings.ToLower(strings.TrimSpace(name))
	hasFailure := len(fields.Values("Failure")) != 0
	hasError := len(fields.Values("Error")) != 0
	hasWarning := len(fields.Values("Warning")) != 0
	if name == "processed" && !annotated && !hasFailure && !hasError && !hasWarning {
		return "processed", ""
	}
	if profile != DispositionProfile {
		return "", ""
	}
	switch {
	case name == "processed/warning" && !hasFailure && !hasError:
		return name, ""
	case name == "processed/error" && !hasFailure && !hasWarning:
		return name, mdnErrorCode(annotation, one(fields, "Error"))
	case (name == "failed" && !annotated || name == "failed/failure") && !hasError && !hasWarning:
		return "failed", ""
	default:
		return "", ""
	}
}

func mdnErrorCode(annotation, detail string) string {
	code := strings.ToLower(strings.TrimSpace(annotation))
	if code == "" {
		code = strings.ToLower(strings.TrimSpace(detail))
	}
	switch code {
	case "authentication-failed", "decompression-failed", "decryption-failed",
		"insufficient-message-security", "integrity-check-failed", "unexpected-processing-error":
		return code
	default:
		return ""
	}
}

var headerEnd = []byte("\r\n\r\n")

func receiptFields(report []byte) (textproto.MIMEHeader, error) {
	if !canonicalCRLF(report) {
		return nil, ErrMDN
	}
	outer, body, err := splitEntity(report)
	if err != nil || !identityEncoding(outer) {
		return nil, ErrMDN
	}
	media, params, err := mime.ParseMediaType(one(outer, "Content-Type"))
	if err != nil || media != "multipart/report" || !strings.EqualFold(params["report-type"], "disposition-notification") ||
		params["boundary"] == "" || len(params["boundary"]) > 70 {
		return nil, ErrMDN
	}
	parts := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	human, err := parts.NextRawPart()
	if err != nil {
		return nil, ErrMDN
	}
	media, _, err = mime.ParseMediaType(one(human.Header, "Content-Type"))
	if err != nil || media != "text/plain" {
		return nil, ErrMDN
	}
	machine, err := parts.NextRawPart()
	if err != nil || !identityEncoding(machine.Header) {
		return nil, ErrMDN
	}
	media, _, err = mime.ParseMediaType(one(machine.Header, "Content-Type"))
	if err != nil || media != "message/disposition-notification" {
		return nil, ErrMDN
	}
	raw, err := io.ReadAll(io.LimitReader(machine, (8<<10)+1))
	if err != nil || len(raw) == 0 || len(raw) > 8<<10 {
		return nil, ErrMDN
	}
	if _, err = parts.NextRawPart(); err != io.EOF {
		return nil, ErrMDN
	}
	header, tail, split := bytes.Cut(raw, headerEnd)
	if split && len(bytes.Trim(tail, "\r\n")) != 0 {
		return nil, ErrMDN
	}
	return readHeader(header)
}

func splitEntity(wire []byte) (textproto.MIMEHeader, []byte, error) {
	header, body, found := bytes.Cut(wire, headerEnd)
	if !found || len(header) > 4<<10 || !canonicalCRLF(header) {
		return nil, nil, ErrMDN
	}
	fields, err := readHeader(header)
	return fields, body, err
}

func canonicalCRLF(wire []byte) bool {
	for pos, value := range wire {
		if value == '\n' && (pos == 0 || wire[pos-1] != '\r') ||
			value == '\r' && (pos == len(wire)-1 || wire[pos+1] != '\n') {
			return false
		}
	}
	return true
}

func sha256MICAlgorithm(raw string) bool {
	algorithm := strings.TrimSpace(raw)
	return strings.EqualFold(algorithm, "sha-256") || strings.EqualFold(algorithm, "sha256")
}

func readHeader(raw []byte) (textproto.MIMEHeader, error) {
	wire := bytes.TrimRight(raw, "\r\n")
	return textproto.NewReader(bufio.NewReader(io.MultiReader(bytes.NewReader(wire), bytes.NewReader(headerEnd)))).ReadMIMEHeader()
}

func identityEncoding(fields textproto.MIMEHeader) bool {
	encoding, ok := mimeTransferEncoding(fields)
	return ok && (encoding == "" || encoding == "7bit")
}

func mimeTransferEncoding(fields textproto.MIMEHeader) (string, bool) {
	values := fields.Values("Content-Transfer-Encoding")
	if len(values) == 0 {
		return "", true
	}
	value := one(fields, "Content-Transfer-Encoding")
	return strings.ToLower(value), value != ""
}

func matchesRecipient(field, expected string) bool {
	kind, value, found := strings.Cut(field, ";")
	return found && strings.EqualFold(strings.TrimSpace(kind), "rfc822") && strings.TrimSpace(value) == expected
}

func one(fields textproto.MIMEHeader, key string) string {
	values := fields.Values(key)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func lowerHexSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func visibleASCII(value string, limit int) bool {
	return len(value) != 0 && len(value) <= limit && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, func(r rune) bool { return r < ' ' || r > '~' })
}
