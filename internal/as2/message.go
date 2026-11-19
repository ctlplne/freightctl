package as2

import (
	"bytes"
	"errors"
	"mime"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

const EncryptedMessageProfile = "as2-authentically-enveloped-signed-mime-v1"

var ErrEncryptedMessage = errors.New("AS2 encrypted message, recipient or inner sender signature could not be verified")

type OpenMessageRequest struct {
	Schema       int    `json:"schema_version"`
	RecipientPin string `json:"recipient_certificate_sha256"`
	SignerPin    string `json:"signer_certificate_sha256"`
}

type OpenedMessage struct {
	Profile      string `json:"profile"`
	EnvelopeSHA  string `json:"envelope_sha256"`
	EntitySHA    string `json:"signed_entity_sha256"`
	EntitySize   int64  `json:"signed_entity_size_bytes"`
	RecipientPin string `json:"recipient_certificate_sha256"`
	SignerPin    string `json:"signer_certificate_sha256"`
}

// OpenEncryptedMessage authenticates the envelope and then checks the sender
// signature over the exact MIME bytes. The caller owns the returned Secret.
func OpenEncryptedMessage(request OpenMessageRequest, envelope, recipient, privateKey, signer []byte, now time.Time) (*secure.Secret, OpenedMessage, error) {
	if request.Schema != 1 || !lowerHexSHA256(request.RecipientPin) || !lowerHexSHA256(request.SignerPin) {
		return nil, OpenedMessage{}, ErrEncryptedMessage
	}
	opened, err := secure.OpenAS2Envelope(envelope, recipient, privateKey, request.RecipientPin, now)
	if err != nil {
		return nil, OpenedMessage{}, ErrEncryptedMessage
	}
	defer opened.Close()
	contentType, body, err := signedCapture(opened.Bytes)
	if err != nil {
		return nil, OpenedMessage{}, ErrEncryptedMessage
	}
	signed, signature, err := signedEntityParts(contentType, body, secure.MaxAS2SignedEntity)
	if err != nil || secure.VerifyAS2DetachedCMS(signed, signature, signer, request.SignerPin, now) != nil {
		return nil, OpenedMessage{}, ErrEncryptedMessage
	}
	header, _, err := splitEntity(signed)
	if err != nil {
		return nil, OpenedMessage{}, ErrEncryptedMessage
	}
	if _, _, err = mime.ParseMediaType(one(header, "Content-Type")); err != nil {
		return nil, OpenedMessage{}, ErrEncryptedMessage
	}
	result := OpenedMessage{
		Profile: EncryptedMessageProfile, EnvelopeSHA: secure.Digest(envelope),
		EntitySHA: secure.Digest(signed), EntitySize: int64(len(signed)),
		RecipientPin: request.RecipientPin, SignerPin: request.SignerPin,
	}
	return secure.ProtectBytes(bytes.Clone(signed)), result, nil
}
