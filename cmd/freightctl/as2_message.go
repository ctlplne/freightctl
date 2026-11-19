package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/ctlplne/freightctl/internal/as2"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/workflow"
)

const as2MessageOpenUsage = "freightctl as2-message-open --request-file <saved certificate pins> --message-file <CMS DER> --recipient-certificate-file <recipient leaf DER> --recipient-key-file <protected PKCS#8 DER> --signer-certificate-file <sender leaf DER> --output <new protected file>"
const as2MessageSealUsage = "freightctl as2-message-seal --request-file <saved certificate pins> --message-file <complete MIME entity> --recipient-certificate-file <recipient leaf DER> --signer-certificate-file <sender leaf DER> --signer-key-file <protected PKCS#8 DER> --output <new protected file>"

func runAS2Message(ctx context.Context, command string, args []string, output io.Writer) error {
	usage, keyFlag, maxInput := as2MessageOpenUsage, "recipient-key-file", secure.MaxAS2Envelope
	seal := command == "as2-message-seal"
	if seal {
		usage, keyFlag, maxInput = as2MessageSealUsage, "signer-key-file", secure.MaxAS2SignedEntity
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestFile := flags.String("request-file", "", "protected original certificate pins")
	messageFile := flags.String("message-file", "", "protected original MIME entity or CMS envelope")
	recipientFile := flags.String("recipient-certificate-file", "", "protected recipient DER certificate")
	keyFile := flags.String(keyFlag, "", "protected PKCS#8 DER key")
	signerFile := flags.String("signer-certificate-file", "", "protected sender DER certificate")
	destination := flags.String("output", "", "new output file inside a private directory")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		_, err := io.WriteString(output, usage+"\n")
		return err
	} else if err != nil || flags.NArg() != 0 || *requestFile == "" || *messageFile == "" || *recipientFile == "" ||
		*keyFile == "" || *signerFile == "" || *destination == "" {
		return errors.New(usage)
	}
	request, err := secure.ReadSecret(*requestFile, 4<<10)
	if err != nil {
		return err
	}
	var expected as2.MessageRequest
	err = workflow.Decode(request.Bytes, &expected)
	request.Close()
	if err != nil {
		return err
	}
	message, err := secure.ReadSecret(*messageFile, int64(maxInput))
	if err != nil {
		return err
	}
	defer message.Close()
	recipient, err := secure.ReadSecret(*recipientFile, secure.MaxAS2Certificate)
	if err != nil {
		return err
	}
	defer recipient.Close()
	signer, err := secure.ReadSecret(*signerFile, secure.MaxAS2Certificate)
	if err != nil {
		return err
	}
	defer signer.Close()
	private, err := secure.ReadSecret(*keyFile, secure.MaxAS2PrivateKey)
	if err != nil {
		return err
	}
	if seal {
		envelope, observed, sealErr := as2.SealEncryptedMessage(expected, message.Bytes, recipient.Bytes, private.Bytes, signer.Bytes, time.Now())
		private.Close()
		if sealErr != nil {
			return sealErr
		}
		if err = writeExchangeBytes(ctx, *destination, int64(len(envelope)), observed.EnvelopeSHA, bytes.NewReader(envelope)); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(observed)
	}
	entity, observed, err := as2.OpenEncryptedMessage(expected, message.Bytes, recipient.Bytes, private.Bytes, signer.Bytes, time.Now())
	private.Close()
	if err != nil {
		return err
	}
	defer entity.Close()
	if err = writeExchangeBytes(ctx, *destination, observed.EntitySize, observed.EntitySHA, bytes.NewReader(entity.Bytes)); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(observed)
}
