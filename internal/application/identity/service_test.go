package identity

import (
	value "asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"testing"
	"time"
)

type fixture struct {
	now                 time.Time
	c                   value.Claims
	p                   value.Policy
	reads               int
	tokenErr, policyErr error
	advance             time.Duration
}

func (f *fixture) Verify(context.Context, string) (value.Claims, error) { return f.c, f.tokenErr }
func (f *fixture) IdentityPolicy(ctx context.Context, issuer string) (value.Policy, error) {
	f.reads++
	f.now = f.now.Add(f.advance)
	return f.p, f.policyErr
}
func newFixture() (*fixture, Service) {
	n := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	f := &fixture{now: n}
	f.c = value.Claims{Issuer: "https://issuer.invalid", Subject: "developer", ClientID: "console", Groups: []string{"team"}, IssuedAt: n.Add(-time.Minute), ExpiresAt: n.Add(time.Minute), KeyUntil: n.Add(20 * time.Second)}
	f.p = value.Policy{Revision: value.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, Issuer: f.c.Issuer, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), Clients: []value.Client{{ID: "console", Kind: value.Human, ClassQualified: true}}, EligibleGroups: []string{"team"}, GroupsAtIssueQualified: true, GroupMaxAge: 5 * time.Minute}
	return f, Service{Tokens: f, Policies: f, Now: func() time.Time { return f.now }}
}
func TestPolicyAndKeyFreshnessAfterWait(t *testing.T) {
	f, s := newFixture()
	if _, err := s.Resolve(context.Background(), "token"); err != nil {
		t.Fatal(err)
	}
	f.advance = 21 * time.Second
	if _, err := s.Resolve(context.Background(), "token"); err == nil {
		t.Fatal("key validity extended during policy read")
	}
	f, s = newFixture()
	f.p.Clients = nil
	if _, err := s.Resolve(context.Background(), "token"); err == nil {
		t.Fatal("revoked client survived")
	}
	f, s = newFixture()
	f.p.EligibleGroups = []string{"another-team"}
	if _, err := s.Resolve(context.Background(), "token"); err == nil {
		t.Fatal("organization removal survived")
	}
}
func TestInvalidTokenDoesNotReadPolicyOrLeakErrors(t *testing.T) {
	f, s := newFixture()
	f.tokenErr = errors.New("private-token-value")
	_, err := s.Resolve(context.Background(), "token")
	if err != value.ErrUnavailable || f.reads != 0 {
		t.Fatalf("unsafe failure: %v reads=%d", err, f.reads)
	}
	f, s = newFixture()
	f.policyErr = errors.New("private-policy-value")
	_, err = s.Resolve(context.Background(), "token")
	if err != value.ErrUnavailable {
		t.Fatal("private policy error escaped")
	}
}
