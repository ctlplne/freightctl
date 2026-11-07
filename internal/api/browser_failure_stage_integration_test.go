//go:build integration

package api

import "testing"

// Never print an arbitrary field from private browser evidence. Only these
// literal journey stages may accompany the existing safe result digest.
func safeNativeBrowserStage(value string) string {
	switch value {
	case "launch", "login", "open-policy", "edit-policy", "accessibility",
		"review-policy", "commit-policy-loss", "retry-policy", "upload",
		"check", "review-release", "release", "download", "login-owner",
		"list-tasks", "open-task", "load-task", "review-request",
		"commit-review-loss", "save-recovery", "reload-review", "restore-review-panel", "reject-foreign-review-recovery", "import-review-recovery",
		"login-reviewer", "approve-review", "adopt-review", "withdraw-review",
		"recover-approval", "editor", "preview", "draft-replay", "activate", "tick-replay", "probe-replay", "admit-replay", "work-replay", "reload-captured", "complete":
		return value
	default:
		return "unavailable"
	}
}

func TestNativeBrowserFailureStageRefusesUntrustedDiagnosticContent(t *testing.T) {
	if safeNativeBrowserStage("login") != "login" {
		t.Fatal("known literal stage missing")
	}
	for _, value := range []string{"", "credential-sentinel", "login\nprivate-sentinel", "https://private.invalid/secret", "/private/path", "LOGIN"} {
		if safeNativeBrowserStage(value) != "unavailable" {
			t.Fatal("untrusted diagnostic content became public")
		}
	}
}
