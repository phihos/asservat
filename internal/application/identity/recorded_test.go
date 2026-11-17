package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

// ADR-335 D5: approval uses the requester's recorded groups only before the
// recorded end of the requester's authentication.
func TestRecordedRequesterEndsAtRecordedExpiry(t *testing.T) {
	start := time.Date(2026, 11, 17, 2, 0, 0, 0, time.UTC)
	now := start
	until := start.Add(10 * time.Second)
	p := value.Principal{Issuer: "https://id.example.invalid", Subject: "dev", ClientID: "console", Kind: value.Human}
	policy := value.Revision{UID: "identity", Generation: 1, Digest: [32]byte{1}}
	r := Recorded(p, []string{"payments-devs"}, []string{"evidence:read", "evidence:capture"}, policy, until, func() time.Time { return now })
	i, err := r.ResolveIdentity(context.Background())
	if err != nil || i.Principal != p || i.Groups[0] != "payments-devs" || i.Policy != policy || !i.Valid(now) || i.ValidUntil.After(until) {
		t.Fatal("recorded requester before expiry", i, err)
	}
	for _, at := range []time.Time{until, until.Add(time.Hour)} {
		now = at
		if _, err = r.ResolveIdentity(context.Background()); !errors.Is(err, value.ErrDenied) {
			t.Fatal("recorded groups used at or after the recorded expiry", at, err)
		}
	}
	now = start
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = r.ResolveIdentity(ctx); !errors.Is(err, value.ErrDenied) {
		t.Fatal("cancelled request resolved", err)
	}
}
