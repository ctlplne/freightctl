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

func openAS2Message(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("as2-message-open", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestFile := flags.String("request-file", "", "protected original certificate pins")
	messageFile := flags.String("message-file", "", "protected original CMS DER")
	recipientFile := flags.String("recipient-certificate-file", "", "protected recipient DER certificate")
	keyFile := flags.String("recipient-key-file", "", "protected PKCS#8 DER key")
	signerFile := flags.String("signer-certificate-file", "", "protected sender DER certificate")
	destination := flags.String("output", "", "new output file inside a private directory")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		_, err := io.WriteString(output, as2MessageOpenUsage+"\n")
		return err
	} else if err != nil || flags.NArg() != 0 || *requestFile == "" || *messageFile == "" || *recipientFile == "" ||
		*keyFile == "" || *signerFile == "" || *destination == "" {
		return errors.New(as2MessageOpenUsage)
	}
	request, err := secure.ReadSecret(*requestFile, 4<<10)
	if err != nil {
		return err
	}
	var expected as2.OpenMessageRequest
	err = workflow.Decode(request.Bytes, &expected)
	request.Close()
	if err != nil {
		return err
	}
	message, err := secure.ReadSecret(*messageFile, secure.MaxAS2Envelope)
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
