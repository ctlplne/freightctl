package as2

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

const EncryptedMessageProfile = "as2-authentically-enveloped-signed-mime-v1"

var ErrEncryptedMessage = errors.New("AS2 encrypted message, recipient or inner sender signature could not be verified")

type MessageRequest struct {
	Schema       int    `json:"schema_version"`
	RecipientPin string `json:"recipient_certificate_sha256"`
	SignerPin    string `json:"signer_certificate_sha256"`
}

type MessageObservation struct {
	Profile      string `json:"profile"`
	EnvelopeSHA  string `json:"envelope_sha256"`
	EntitySHA    string `json:"signed_entity_sha256"`
	EntitySize   int64  `json:"signed_entity_size_bytes"`
	RecipientPin string `json:"recipient_certificate_sha256"`
	SignerPin    string `json:"signer_certificate_sha256"`
}

// OpenEncryptedMessage authenticates the envelope and then checks the sender
// signature over the exact MIME bytes. The caller owns the returned Secret.
func OpenEncryptedMessage(request MessageRequest, envelope, recipient, privateKey, signer []byte, now time.Time) (*secure.Secret, MessageObservation, error) {
	if !validMessageRequest(request) {
		return nil, MessageObservation{}, ErrEncryptedMessage
	}
	opened, err := secure.OpenAS2Envelope(envelope, recipient, privateKey, request.RecipientPin, now)
	if err != nil {
		return nil, MessageObservation{}, ErrEncryptedMessage
	}
	defer opened.Close()
	contentType, body, err := signedCapture(opened.Bytes)
	if err != nil {
		return nil, MessageObservation{}, ErrEncryptedMessage
	}
	signed, signature, err := signedEntityParts(contentType, body, secure.MaxAS2SignedEntity)
	if err != nil || secure.VerifyAS2DetachedCMS(signed, signature, signer, request.SignerPin, now) != nil {
		return nil, MessageObservation{}, ErrEncryptedMessage
	}
	if !validMessageEntity(signed) {
		return nil, MessageObservation{}, ErrEncryptedMessage
	}
	return secure.ProtectBytes(bytes.Clone(signed)), observeEncryptedMessage(request, envelope, signed), nil
}

// SealEncryptedMessage signs the original MIME bytes before enciphering the
// resulting multipart for the pinned recipient.
func SealEncryptedMessage(request MessageRequest, entity, recipient, privateKey, signer []byte, now time.Time) ([]byte, MessageObservation, error) {
	if !validMessageRequest(request) || !validMessageEntity(entity) {
		return nil, MessageObservation{}, ErrEncryptedMessage
	}
	signature, err := secure.SignAS2DetachedCMS(entity, signer, privateKey, request.SignerPin, now)
	if err != nil {
		return nil, MessageObservation{}, ErrEncryptedMessage
	}
	boundary := "freightctl-as2-" + secure.NewID()
	marker := []byte("--" + boundary)
	if bytes.HasPrefix(entity, marker) || bytes.Contains(entity, []byte("\r\n--"+boundary)) {
		return nil, MessageObservation{}, ErrEncryptedMessage
	}
	var signed bytes.Buffer
	signed.Grow(len(entity) + base64.StdEncoding.EncodedLen(len(signature)) + 2048)
	fmt.Fprintf(&signed, "MIME-Version: 1.0\r\nContent-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"%s\"\r\n\r\n--%s\r\n", boundary, boundary)
	signed.Write(entity)
	fmt.Fprintf(&signed, "\r\n--%s\r\nContent-Type: application/pkcs7-signature\r\nContent-Transfer-Encoding: base64\r\n\r\n", boundary)
	for encoded := base64.StdEncoding.AppendEncode(nil, signature); len(encoded) != 0; {
		width := min(64, len(encoded))
		signed.Write(encoded[:width])
		signed.WriteString("\r\n")
		encoded = encoded[width:]
	}
	fmt.Fprintf(&signed, "--%s--\r\n", boundary)
	signedBuffer := secure.ProtectBytes(signed.Bytes())
	defer signedBuffer.Close()
	envelope, err := secure.SealAS2Envelope(signedBuffer.Bytes, recipient, request.RecipientPin, now)
	if err != nil {
		return nil, MessageObservation{}, ErrEncryptedMessage
	}
	return envelope, observeEncryptedMessage(request, envelope, entity), nil
}

func validMessageRequest(request MessageRequest) bool {
	return request.Schema == 1 && lowerHexSHA256(request.RecipientPin) && lowerHexSHA256(request.SignerPin)
}

func validMessageEntity(entity []byte) bool {
	if len(entity) == 0 || len(entity) > secure.MaxAS2SignedEntity {
		return false
	}
	header, _, err := splitEntity(entity)
	if err != nil {
		return false
	}
	_, _, err = mime.ParseMediaType(one(header, "Content-Type"))
	return err == nil
}

func observeEncryptedMessage(request MessageRequest, envelope, signed []byte) MessageObservation {
	return MessageObservation{
		Profile: EncryptedMessageProfile, EnvelopeSHA: secure.Digest(envelope),
		EntitySHA: secure.Digest(signed), EntitySize: int64(len(signed)),
		RecipientPin: request.RecipientPin, SignerPin: request.SignerPin,
	}
}
