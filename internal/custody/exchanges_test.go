package custody

import (
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestExchangeConfigurationRefusesUnusableLifetimeBeforeDatabaseUse(t *testing.T) {
	valid := ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128}
	for _, duration := range []time.Duration{0, -time.Second, time.Nanosecond, time.Microsecond, time.Second + time.Nanosecond} {
		settings := valid
		settings.MaxLifetime = duration
		service := &Service{MaxFile: 1024, Exchanges: settings}
		if _, _, err := service.ExchangeLimits(); !errors.Is(err, store.ErrState) {
			t.Fatalf("unusable lifetime %s accepted", duration)
		}
	}
	service := &Service{MaxFile: 1024, Exchanges: valid}
	limits, maximum, err := service.ExchangeLimits()
	if err != nil || limits.MaxArtifactBytes != 1024 || limits.MaxLifetime != time.Hour || maximum != 128 {
		t.Fatal("trusted configuration did not bind admission", err)
	}
}
