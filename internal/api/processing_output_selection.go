package api

import (
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"

	"github.com/ctlplne/freightctl/internal/checks"
	"github.com/ctlplne/freightctl/internal/store"
)

func processingOutputReference(query string) (*store.OnboardingReference, error) {
	if query == "" {
		return nil, nil
	}
	if len(query) > 1024 {
		return nil, checks.ErrInput
	}
	values, err := url.ParseQuery(query)
	if err != nil || len(values) != 3 {
		return nil, checks.ErrInput
	}
	for _, key := range []string{"output_policy_id", "output_policy_version", "output_policy_hash"} {
		if len(values[key]) != 1 || values[key][0] == "" {
			return nil, checks.ErrInput
		}
	}
	version, err := strconv.Atoi(values.Get("output_policy_version"))
	hash := values.Get("output_policy_hash")
	if err != nil || version < 1 || !store.ValidID(values.Get("output_policy_id")) || len(hash) != 64 || hash != strings.ToLower(hash) {
		return nil, checks.ErrInput
	}
	if _, err = hex.DecodeString(hash); err != nil {
		return nil, checks.ErrInput
	}
	return &store.OnboardingReference{ID: values.Get("output_policy_id"), Version: version, Hash: hash}, nil
}
