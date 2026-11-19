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

const as2MDNUsage = "freightctl as2-mdn-verify --request-file <saved expectation> --signer-certificate-file <pinned peer DER> (--receipt-file <multipart/signed MIME capture> | --report-file <signed MIME entity> --signature-file <detached CMS DER>) [--receipt-profile as2-signed-disposition-sha256-v1]"

func verifyAS2MDN(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("as2-mdn-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestFile := flags.String("request-file", "", "protected original AS2 message expectation")
	receiptFile := flags.String("receipt-file", "", "protected complete multipart/signed receipt MIME entity")
	reportFile := flags.String("report-file", "", "protected exact signed report MIME bytes")
	signatureFile := flags.String("signature-file", "", "protected detached CMS signature")
	signerFile := flags.String("signer-certificate-file", "", "protected pinned DER certificate")
	profile := flags.String("receipt-profile", as2.VerificationProfile, "AS2 receipt verification profile")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		_, err := io.WriteString(output, as2MDNUsage+"\n")
		return err
	} else if err != nil || flags.NArg() != 0 || *requestFile == "" || *signerFile == "" {
		return errors.New(as2MDNUsage)
	}
	captureMode := *receiptFile != "" && *reportFile == "" && *signatureFile == ""
	detachedMode := *receiptFile == "" && *reportFile != "" && *signatureFile != ""
	if (!captureMode && !detachedMode) || !as2.ValidMDNProfile(*profile) {
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
	signer, err := secure.ReadSecret(*signerFile, secure.MaxAS2Certificate)
	if err != nil {
		return err
	}
	defer signer.Close()

	var observed as2.VerifiedMDN
	if captureMode {
		capture, openErr := secure.ReadSecret(*receiptFile, as2.MaxSignedMDN)
		if openErr != nil {
			return openErr
		}
		defer capture.Close()
		observed, err = as2.VerifyMDNCapture(*profile, expected, capture.Bytes, signer.Bytes, time.Now())
	} else {
		report, openErr := secure.ReadSecret(*reportFile, secure.MaxAS2SignedReport)
		if openErr != nil {
			return openErr
		}
		defer report.Close()
		signature, openErr := secure.ReadSecret(*signatureFile, secure.MaxAS2CMSSignature)
		if openErr != nil {
			return openErr
		}
		defer signature.Close()
		observed, err = as2.VerifyMDN(*profile, expected, report.Bytes, signature.Bytes, signer.Bytes, time.Now())
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(observed)
}
