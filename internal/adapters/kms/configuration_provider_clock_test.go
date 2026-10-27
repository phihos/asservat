package kms

import (
	"net/http"
	"testing"
	"time"
)

// A login can straddle a wall-clock second under CI scheduling. The healthy
// hint fixture must not turn that delay into a future provider creation date.
func TestConfigurationProviderHealthyFixtureKeepsClockAcrossLoginBoundary(t *testing.T) {
	now := time.Now().UTC()
	s, _ := configurationJoinFixtureWithClock(t, func() time.Time { return now })
	control := s.effects.wrap.control
	original := control.http.Transport
	if closeable, ok := original.(interface{ CloseIdleConnections() }); ok {
		defer closeable.CloseIdleConnections()
	}
	boundary := now.Truncate(time.Second).Add(time.Second + 10*time.Millisecond)
	control.http.Transport = ownerLeaseRoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/v1/auth/owner-auth/login" {
			timer := time.NewTimer(max(0, time.Until(boundary)))
			defer timer.Stop()
			select {
			case <-request.Context().Done():
				return nil, request.Context().Err()
			case <-timer.C:
			}
		}
		return original.RoundTrip(request)
	})
	if err := s.effects.wrap.refresh(t.Context()); err != nil {
		t.Fatal("synthetic fixture clocks disagree after delayed login", err)
	}
}
