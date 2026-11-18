package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/ctlplne/freightctl/internal/as2"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/workflow"
)

const as2MDNUsage = "freightctl as2-mdn-verify --request-file <saved expectation> --report-file <signed MIME entity> --signature-file <detached CMS DER> --signer-certificate-file <pinned peer DER>"

func verifyAS2MDN(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("as2-mdn-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestFile := flags.String("request-file", "", "protected original AS2 message expectation")
	reportFile := flags.String("report-file", "", "protected exact signed report MIME bytes")
	signatureFile := flags.String("signature-file", "", "protected detached CMS signature")
	signerFile := flags.String("signer-certificate-file", "", "protected pinned DER certificate")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		_, err := io.WriteString(output, as2MDNUsage+"\n")
		return err
	} else if err != nil || flags.NArg() != 0 || *requestFile == "" || *reportFile == "" || *signatureFile == "" || *signerFile == "" {
		return errors.New(as2MDNUsage)
	}
	request, err := secure.ReadSecret(*requestFile, 4<<10)
	if err != nil {
		return err
	}
	var expected as2.ExpectedMDN
	err = workflow.Decode(request.Bytes, &expected)
	request.Close()
	if err != nil {
		return err
	}
	report, err := secure.ReadSecret(*reportFile, secure.MaxAS2SignedReport)
	if err != nil {
		return err
	}
	defer report.Close()
	signature, err := secure.ReadSecret(*signatureFile, secure.MaxAS2CMSSignature)
	if err != nil {
		return err
	}
	defer signature.Close()
	signer, err := secure.ReadSecret(*signerFile, secure.MaxAS2Certificate)
	if err != nil {
		return err
	}
	defer signer.Close()
	observed, err := as2.VerifyPositiveMDN(expected, report.Bytes, signature.Bytes, signer.Bytes, time.Now())
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(observed)
}
