package main

import (
	"context"
	"encoding/json"
	"errors"
)

type sourceFailure string

func (sourceFailure) Error() string { return "FTPS source fixture contract failed" }

const (
	sourceDatabaseFailure sourceFailure = "database"
	sourceServeFailure    sourceFailure = "serve"
	sourceCloseFailure    sourceFailure = "listener-close"
	sourceSaveFailure     sourceFailure = "witness-save"
	sourceBudgetFailure   sourceFailure = "contact-budget"
	sourceLifetimeFailure sourceFailure = "lifetime-expired"
)

func sourceShutdownFailure(serve, close, save error, exhausted bool, contextError error) error {
	switch {
	case serve != nil:
		return sourceServeFailure
	case close != nil:
		return sourceCloseFailure
	case save != nil:
		return sourceSaveFailure
	case exhausted:
		return sourceBudgetFailure
	case errors.Is(contextError, context.DeadlineExceeded):
		return sourceLifetimeFailure
	}
	return nil
}

func sourceFailureDiagnostic(err error) []byte {
	stage := "unclassified"
	var failure sourceFailure
	if errors.As(err, &failure) {
		switch failure {
		case sourceDatabaseFailure, sourceServeFailure, sourceCloseFailure, sourceSaveFailure, sourceBudgetFailure, sourceLifetimeFailure:
			stage = string(failure)
		}
	}
	raw, _ := json.Marshal(struct {
		Kind  string `json:"kind"`
		Stage string `json:"stage"`
	}{"freightctl-ftps-source-failure-v1", stage})
	return append(raw, '\n')
}
