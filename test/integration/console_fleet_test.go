package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/browser"
)

// Synthetic issuance state only. The actual FleetHandler still authenticates
// the browser cookie, current identity and CSRF before this typed service.
type consoleSyntheticFleet struct {
	mu       sync.Mutex
	calls    []fleetapp.FleetBootstrapRequest
	reserved int
	original value.BootstrapIntent
}

func newConsoleFleet(t *testing.T, session browser.SessionHandler) (*browser.FleetHandler, *consoleSyntheticFleet) {
	t.Helper()
	s := &consoleSyntheticFleet{}
	h, err := browser.NewFleetHandler(session, s)
	if err != nil {
		t.Fatal(err)
	}
	return h, s
}

func (s *consoleSyntheticFleet) Issue(ctx context.Context, current app.CurrentIdentity, in fleetapp.FleetBootstrapRequest) (value.BootstrapIntent, error) {
	if _, err := current.ResolveIdentity(ctx); err != nil {
		return value.BootstrapIntent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, in)
	if len(s.calls) > 2 {
		return value.BootstrapIntent{}, value.ErrDenied
	}
	if s.reserved == 0 {
		now := time.Now().UTC().Truncate(time.Microsecond)
		s.original = value.BootstrapIntent{Issued: true, Credential: &value.BootstrapCredential{Version: 1, SecretDigest: artifact.Digest{9}},
			Slot: value.BootstrapSlot{ID: consoleCaptureID(601), Binding: value.PeerBinding{InstallationID: consoleCaptureID(602), ClusterID: consoleCaptureID(603), PeerID: consoleCaptureID(604), IssuerEpoch: consoleCaptureID(605), Role: value.ConnectorPeer},
				DeliveryProfile: in.DeliveryProfile, NotBefore: now, NotAfter: now.Add(5 * time.Minute)}}
		s.reserved++
		// Model a completed issuance whose public reply was uncertain. The
		// next explicit request must resolve this same slot, never reserve again.
		return value.BootstrapIntent{}, value.ErrUnavailable
	}
	if in != s.calls[0] {
		return value.BootstrapIntent{}, value.ErrInvalid
	}
	return s.original, nil
}

func (s *consoleSyntheticFleet) check(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reserved != 1 || len(s.calls) != 3 || s.calls[0] != s.calls[1] || s.calls[2].IdempotencyKey == s.calls[0].IdempotencyKey ||
		s.calls[0].DisplayName != "Workload cluster" || s.calls[0].Region != "eu-test" || s.calls[0].DeliveryProfile != "regional-installer" || s.original.Slot.NotAfter.Sub(s.original.Slot.NotBefore) != 5*time.Minute {
		t.Fatal("Fleet browser changed the original request, slot count or finite lifetime")
	}
}
