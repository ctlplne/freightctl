package main

import (
	"context"
	"testing"
	"time"
)

func TestSourceRuntimeContextUsesPlatformLifetimeOnlyOnGitHub(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	ctx, cancel := sourceRuntimeContext(context.Background())
	defer cancel()
	if _, deadline := ctx.Deadline(); deadline {
		t.Fatal("GitHub source fixture acquired an arbitrary whole-journey deadline")
	}
	cancel()
	if ctx.Err() != context.Canceled {
		t.Fatal("explicit task-owned source stop did not cancel")
	}
}

func TestSourceRuntimeContextPreservesLocalAllowanceAndParentCancellation(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "false")
	before := time.Now()
	local, stop := sourceRuntimeContext(t.Context())
	defer stop()
	deadline, ok := local.Deadline()
	if !ok || deadline.Before(before.Add(3*time.Minute)) || deadline.After(time.Now().Add(3*time.Minute)) {
		t.Fatal("local source fixture allowance changed")
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	parent, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	child, closeChild := sourceRuntimeContext(parent)
	defer closeChild()
	want, _ := parent.Deadline()
	got, inherited := child.Deadline()
	if !inherited || !got.Equal(want) {
		t.Fatal("GitHub fixture discarded an actual parent operation deadline")
	}
	cancel()
	if child.Err() != context.Canceled {
		t.Fatal("GitHub fixture ignored owner cancellation")
	}
}
