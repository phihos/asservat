package identity

import (
	value "asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"testing"
	"time"
)

func TestSchedulePolicyOnlyShortensVerifiedBoundsAndDoesNotVerifyToken(t *testing.T) {
	f, s := newFixture()
	f.c.IssuedAt = f.now.Add(-10 * time.Second)
	v, e := s.ObserveCredential(t.Context(), "synthetic")
	if e != nil {
		t.Fatal(e)
	}
	f.now = f.now.Add(6 * time.Second)
	f.p.ObservedAt = f.now
	f.p.FreshUntil = f.now.Add(5 * time.Second)
	f.p.GroupMaxAge = 40 * time.Second
	f.tokenErr = errors.New("token verifier must not be called by schedule observation")
	next, e := s.ShortenCredentialWindow(t.Context(), v.Identity.Principal, v.Window)
	if e != nil {
		t.Fatal(e)
	}
	if !next.IssuedAt.Equal(v.Window.IssuedAt) || !next.TokenExpiresAt.Equal(v.Window.TokenExpiresAt) || !next.GroupsExpireAt.Equal(f.c.IssuedAt.Add(40*time.Second)) || !next.RefreshAt(f.now.Add(time.Hour)).Before(v.Window.RefreshAt(f.now.Add(time.Hour))) {
		t.Fatal("policy did not preserve and shorten original verified schedule")
	}
	f.p.GroupMaxAge = 5 * time.Minute
	raised, e := s.ShortenCredentialWindow(t.Context(), v.Identity.Principal, next)
	if e != nil || !raised.GroupsExpireAt.Equal(next.GroupsExpireAt) {
		t.Fatal("raised policy extended old credential", e)
	}
	// This scheduling-only value can never substitute current identity: a full
	// current resolver must still invoke the verifier and deny its actual failure.
	if _, e = s.Resolve(t.Context(), "synthetic"); !errors.Is(e, value.ErrUnavailable) {
		t.Fatal("scheduling result became identity", e)
	}
}
func TestSchedulePolicyRetainsOriginalWaitAndRejectsRevokedClient(t *testing.T) {
	for _, kind := range []string{"wait", "expired-groups", "client", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f, s := newFixture()
			v, e := s.ObserveCredential(t.Context(), "synthetic")
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch kind {
			case "wait":
				f.advance = 6 * time.Second
			case "expired-groups":
				f.p.GroupMaxAge = 30 * time.Second
			case "client":
				f.p.Clients[0].ID = "replacement"
			case "cancel":
				cancel()
			}
			if _, e = s.ShortenCredentialWindow(ctx, v.Identity.Principal, v.Window); e == nil {
				t.Fatal("invalid current scheduling source survived", kind)
			}
		})
	}
}
