package as2

import (
	"bytes"
	"encoding/base64"
	"errors"
	"mime"
	"strings"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

const MaxSignedMDN = 128 << 10

var ErrSignedMDN = errors.New("AS2 signed receipt container is invalid or outside its supported MIME profile")

// VerifyMDNCapture takes a saved MIME entity with its outer Content-Type and
// exact body bytes. Its MIME headers select framing only.
func VerifyMDNCapture(profile string, expected ExpectedMDN, capture, certificate []byte, now time.Time) (VerifiedMDN, error) {
	if len(capture) > MaxSignedMDN {
		return VerifiedMDN{}, ErrSignedMDN
	}
	contentType, body, err := signedCapture(capture)
	if err != nil {
		return VerifiedMDN{}, err
	}
	return VerifySignedMDN(profile, expected, contentType, body, certificate, now)
}

func signedCapture(capture []byte) (string, []byte, error) {
	fields, body, err := splitEntity(capture)
	if err != nil {
		return "", nil, ErrSignedMDN
	}
	encoding, ok := mimeTransferEncoding(fields)
	if !ok {
		return "", nil, ErrSignedMDN
	}
	switch encoding {
	case "", "7bit", "8bit", "binary":
		return one(fields, "Content-Type"), body, nil
	default:
		return "", nil, ErrSignedMDN
	}
}

// VerifySignedMDN accepts the Content-Type and body as separate inputs for
// callers that already have MIME metadata, including an AS2 HTTP response.
func VerifySignedMDN(profile string, expected ExpectedMDN, contentType string, body, certificate []byte, now time.Time) (VerifiedMDN, error) {
	if len(body) > MaxSignedMDN {
		return VerifiedMDN{}, ErrSignedMDN
	}
	report, signature, err := signedEntityParts(contentType, body, secure.MaxAS2SignedReport)
	if err != nil {
		return VerifiedMDN{}, err
	}
	return VerifyMDN(profile, expected, report, signature, certificate, now)
}

func signedEntityParts(contentType string, body []byte, maxEntity int) ([]byte, []byte, error) {
	if len(contentType) > 4<<10 {
		return nil, nil, ErrSignedMDN
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	protocol := strings.ToLower(params["protocol"])
	boundary := params["boundary"]
	if err != nil || mediaType != "multipart/signed" ||
		(protocol != "application/pkcs7-signature" && protocol != "application/x-pkcs7-signature") ||
		!sha256MICAlgorithm(params["micalg"]) || !validMIMEBoundary(boundary) {
		return nil, nil, ErrSignedMDN
	}
	report, signaturePart, ok := originalSignedParts(body, boundary)
	if !ok || len(report) == 0 || len(report) > maxEntity {
		return nil, nil, ErrSignedMDN
	}
	signature, err := detachedSignature(signaturePart, protocol)
	if err != nil {
		return nil, nil, err
	}
	return report, signature, nil
}

func validMIMEBoundary(boundary string) bool {
	if len(boundary) == 0 || len(boundary) > 70 || boundary[len(boundary)-1] == ' ' {
		return false
	}
	for _, c := range boundary {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.ContainsRune("'()+_,-./:=? ", c)) {
			return false
		}
	}
	return true
}

// Slice the capture before interpreting the inner MIME entity. The CRLF
// introducing a delimiter belongs to that delimiter. Any earlier CRLF at
// the end of the signed part remains in the bytes passed to CMS.
func originalSignedParts(body []byte, boundary string) ([]byte, []byte, bool) {
	marker := []byte("--" + boundary)
	var parts [2][]byte
	count, partStart := 0, -1
	for offset := 0; offset < len(body); {
		line, _, terminated := bytes.Cut(body[offset:], []byte("\r\n"))
		next := offset + len(line)
		if terminated {
			next += 2
		}
		if bytes.HasPrefix(line, marker) {
			ending := bytes.TrimRight(line[len(marker):], " \t")
			closing := bytes.Equal(ending, []byte("--"))
			if !closing && (len(ending) != 0 || !terminated) {
				return nil, nil, false
			}
			if partStart >= 0 {
				if count >= len(parts) || offset-2 < partStart {
					return nil, nil, false
				}
				parts[count] = body[partStart : offset-2]
				count++
			}
			if closing {
				return parts[0], parts[1], count == len(parts)
			}
			partStart = next
		}
		offset = next
	}
	return nil, nil, false
}

func detachedSignature(part []byte, protocol string) ([]byte, error) {
	fields, body, err := splitEntity(part)
	if err != nil {
		return nil, ErrSignedMDN
	}
	mediaType, _, err := mime.ParseMediaType(one(fields, "Content-Type"))
	if err != nil || mediaType != protocol {
		return nil, ErrSignedMDN
	}
	transfer, ok := mimeTransferEncoding(fields)
	if !ok {
		return nil, ErrSignedMDN
	}
	switch transfer {
	case "", "binary":
		// The HTTP AS2 examples also carry DER without a transfer-encoding field.
	case "base64":
		// Stock S/MIME emitters can use LF folds in the encoded signature
		// with CRLF throughout the surrounding MIME and the signed report.
		folded := bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
		encoded := bytes.ReplaceAll(folded, []byte("\n"), nil)
		if bytes.IndexByte(encoded, '\r') >= 0 || len(encoded) > base64.StdEncoding.EncodedLen(secure.MaxAS2CMSSignature) {
			return nil, ErrSignedMDN
		}
		body, err = base64.StdEncoding.Strict().AppendDecode(nil, encoded)
		if err != nil {
			return nil, ErrSignedMDN
		}
	default:
		return nil, ErrSignedMDN
	}
	if len(body) == 0 || len(body) > secure.MaxAS2CMSSignature {
		return nil, ErrSignedMDN
	}
	return body, nil
}
