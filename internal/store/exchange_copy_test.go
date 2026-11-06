package store

import (
	"strings"
	"testing"
)

func TestReceivedCopyMeaningBindsSourceAndDestinationWithoutGrant(t *testing.T) {
	r := ExchangeCopyRequest{ExchangeCopyOrigin: ExchangeCopyOrigin{ExchangeID: "11111111-1111-4111-8111-111111111111", RequestHash: strings.Repeat("a", 64), Artifact: ExchangeArtifact{ID: "22222222-2222-4222-8222-222222222222", Size: 8, SHA256: strings.Repeat("b", 64), Policy: "integrity-only-v1"}}, Path: "/owned.dat"}
	if err := ValidateExchangeCopy(r, 1024); err != nil {
		t.Fatal("valid exact-copy metadata", err)
	}
	base := ExchangeCopyMeaning(r, "ordinary-target-binding")
	for _, mutate := range []func(*ExchangeCopyRequest){func(v *ExchangeCopyRequest) { v.ExchangeID = "33333333-3333-4333-8333-333333333333" }, func(v *ExchangeCopyRequest) { v.RequestHash = strings.Repeat("c", 64) }, func(v *ExchangeCopyRequest) { v.Artifact.ID = "44444444-4444-4444-8444-444444444444" }, func(v *ExchangeCopyRequest) { v.Artifact.Policy = "different" }, func(v *ExchangeCopyRequest) { v.Path = "/other.dat" }} {
		v := r
		mutate(&v)
		if ExchangeCopyMeaning(v, "ordinary-target-binding") == base {
			t.Fatal("different source or destination replayed the original key")
		}
	}
	if ExchangeCopyMeaning(r, "other-root-resolved-target") == base {
		t.Fatal("different authenticated root reused receipt")
	}
	for _, path := range []string{"/", "/../escape", "/a/../b", "relative", "/.freightctl/uploads/x"} {
		v := r
		v.Path = path
		if ValidateExchangeCopy(v, 1024) == nil {
			t.Fatal("unsafe destination", path)
		}
	}
	v := r
	v.Artifact.Size = 1025
	if ValidateExchangeCopy(v, 1024) == nil {
		t.Fatal("new copy exceeded configured file allowance")
	}
}
