package integration

import (
	"context"
	"slices"
	"testing"
	"time"

	authorizationapp "asservat.local/asservat/internal/application/authorization"
	identityapp "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/identity"
)

// Synthetic session storage only. NewBrowserRequest, the current authority gate,
// SQL roles/locks, encrypted S3 audit, TLS and process-owned worker key are real.
// This is neither a deployed worker nor a Keycloak/Pod-proof/provider fixture.
type workerBrowserSession struct {
	initial  identity.Identity
	expires  time.Time
	interval time.Duration
}

func (s workerBrowserSession) Resolve(ctx context.Context, cookie string, refresh bool) (identityapp.SessionView, error) {
	if ctx.Err() != nil || cookie != "synthetic-worker-session" || refresh {
		return identityapp.SessionView{}, identity.ErrDenied
	}
	i := s.initial
	i.Groups, i.Scopes = slices.Clone(i.Groups), slices.Clone(i.Scopes)
	i.VerifiedAt = time.Now().UTC()
	i.ValidUntil = identity.Earlier(i.VerifiedAt.Add(s.interval), s.expires)
	return identityapp.SessionView{Identity: i, ExpiresAt: s.expires}, nil
}
func browserCurrentForWorkerTest(t *testing.T, ctx context.Context, gate authorizationapp.ContextDownloadAuthority, interval time.Duration) (identityapp.CurrentIdentity, time.Time) {
	t.Helper()
	// This existing fixture reference only seeds its synthetic session store.
	// No product CurrentIdentity path serializes or fabricates a bearer token.
	i, err := gate.Identities.Resolve(ctx, "synthetic-reference")
	if err != nil {
		t.Fatal(err)
	}
	current, v, err := identityapp.NewBrowserRequest(ctx, workerBrowserSession{i, time.Now().UTC().Add(time.Minute), interval}, "synthetic-worker-session", false, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return current, v.Identity.ValidUntil
}
