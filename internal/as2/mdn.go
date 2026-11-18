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

const VerificationProfile = "as2-detached-positive-mdn-sha256-v1"

var ErrMDN = errors.New("AS2 MDN is outside the verified positive receipt profile or differs from the original message")

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
	ContentMIC         string `json:"content_mic_sha256"`
	SignerSHA256       string `json:"signer_certificate_sha256"`
	ReportSHA256       string `json:"signed_report_sha256"`
	SignatureSHA256    string `json:"signature_sha256"`
	ReceiverDurability string `json:"receiver_durability"`
	BusinessAcceptance string `json:"business_acceptance"`
}

func VerifyPositiveMDN(expected ExpectedMDN, report, signature, certificate []byte, now time.Time) (VerifiedMDN, error) {
	if expected.Schema != 1 || !visibleASCII(expected.OriginalMessageID, 998) ||
		!visibleASCII(expected.FinalRecipient, 128) || !lowerHexSHA256(expected.ContentMIC) || !lowerHexSHA256(expected.SignerPin) {
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
	mode, disposition, found := strings.Cut(one(fields, "Disposition"), ";")
	if !found || !strings.EqualFold(strings.TrimSpace(mode), "automatic-action/MDN-sent-automatically") ||
		!strings.EqualFold(strings.TrimSpace(disposition), "processed") ||
		len(fields.Values("Failure")) != 0 || len(fields.Values("Error")) != 0 || len(fields.Values("Warning")) != 0 {
		return VerifiedMDN{}, ErrMDN
	}
	value, algorithm, found := strings.Cut(one(fields, "Received-Content-Mic"), ",")
	algorithm = strings.ToLower(strings.TrimSpace(algorithm))
	if !found || (algorithm != "sha-256" && algorithm != "sha256") {
		return VerifiedMDN{}, ErrMDN
	}
	mic, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(value))
	if err != nil || len(mic) != 32 || hex.EncodeToString(mic) != expected.ContentMIC {
		return VerifiedMDN{}, ErrMDN
	}
	return VerifiedMDN{
		Profile: VerificationProfile, Disposition: "processed", MessageIDSHA256: secure.Digest([]byte(expected.OriginalMessageID)),
		ContentMIC: expected.ContentMIC, SignerSHA256: expected.SignerPin, ReportSHA256: secure.Digest(report),
		SignatureSHA256: secure.Digest(signature), ReceiverDurability: "unknown", BusinessAcceptance: "unknown",
	}, nil
}

var headerEnd = []byte("\r\n\r\n")

func receiptFields(report []byte) (textproto.MIMEHeader, error) {
	for pos, value := range report {
		if value == '\n' && (pos == 0 || report[pos-1] != '\r') ||
			value == '\r' && (pos == len(report)-1 || report[pos+1] != '\n') {
			return nil, ErrMDN
		}
	}
	header, body, found := bytes.Cut(report, headerEnd)
	if !found || len(header) > 4<<10 {
		return nil, ErrMDN
	}
	outer, err := readHeader(header)
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

func readHeader(raw []byte) (textproto.MIMEHeader, error) {
	wire := bytes.TrimRight(raw, "\r\n")
	return textproto.NewReader(bufio.NewReader(io.MultiReader(bytes.NewReader(wire), bytes.NewReader(headerEnd)))).ReadMIMEHeader()
}

func identityEncoding(fields textproto.MIMEHeader) bool {
	values := fields.Values("Content-Transfer-Encoding")
	return len(values) == 0 || (len(values) == 1 && strings.EqualFold(values[0], "7bit"))
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
