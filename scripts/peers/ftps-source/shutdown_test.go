package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSourceShutdownCannotReportSuccessAfterLifetimeExpired(t *testing.T) {
	if sourceShutdownFailure(nil, nil, nil, false, context.DeadlineExceeded) == nil {
		t.Fatal("source silently reported clean requested shutdown after its fixture lifetime expired")
	}
	if sourceShutdownFailure(nil, nil, nil, false, context.Canceled) != nil {
		t.Fatal("clean explicitly requested stop became failure")
	}
}

func TestSourceShutdownFailureKeepsOnlyClosedCategories(t *testing.T) {
	private := errors.New("PRIVATE_CREDENTIAL_PATH")
	for _, c := range []struct {
		serve, close, save, contextError error
		exhausted                        bool
		stage                            string
	}{
		{serve: private, stage: "serve"},
		{serve: private, contextError: context.DeadlineExceeded, stage: "serve"},
		{close: private, stage: "listener-close"},
		{save: private, stage: "witness-save"},
		{exhausted: true, stage: "contact-budget"},
		{contextError: context.DeadlineExceeded, stage: "lifetime-expired"},
	} {
		err := sourceShutdownFailure(c.serve, c.close, c.save, c.exhausted, c.contextError)
		wire := string(sourceFailureDiagnostic(err))
		if err == nil || !strings.Contains(wire, `"stage":"`+c.stage+`"`) || strings.Contains(wire, "PRIVATE_") {
			t.Fatal("source failure lost its closed category or disclosed private error")
		}
	}
	for _, err := range []error{private, sourceFailure("PRIVATE_CANARY")} {
		if string(sourceFailureDiagnostic(err)) != "{\"kind\":\"freightctl-ftps-source-failure-v1\",\"stage\":\"unclassified\"}\n" {
			t.Fatal("untrusted source failure became a public diagnostic")
		}
	}
}
