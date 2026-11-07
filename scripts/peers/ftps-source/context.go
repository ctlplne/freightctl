package main

import (
	"context"
	"os"
	"time"
)

func sourceRuntimeContext(parent context.Context) (context.Context, context.CancelFunc) {
	// S004 leaves the GitHub fixture aggregate to its platform/owner lifetime.
	// Session,request,contact and exact-child shutdown bounds stay separate.
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, 3*time.Minute)
}
