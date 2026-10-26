package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

func TestPreviewSharingChecksScopeIssuerAndEnd(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	owner := identity.Identity{Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "owner", ClientID: "console", Kind: identity.Human}, Scopes: []string{"evidence:read", "evidence:capture", authorization.ShareScope}}
	share := func(issuer string, end time.Time) *value.ContextSharing {
		return &value.ContextSharing{Recipients: []authorization.ShareRecipient{{Kind: "Group", Issuer: issuer, ID: "incident-team"}}, NotAfter: end}
	}
	if err := previewSharing(nil, identity.Identity{}, now); err != nil {
		t.Fatal("no instruction refused", err)
	}
	if err := previewSharing(share(owner.Principal.Issuer, time.Time{}), owner, now); err != nil {
		t.Fatal("default end refused", err)
	}
	if err := previewSharing(share(owner.Principal.Issuer, now.Add(authorization.ShareMaxLifetime)), owner, now); err != nil {
		t.Fatal("seven-day end refused", err)
	}
	noScope := owner
	noScope.Scopes = []string{"evidence:read", "evidence:capture"}
	policy := owner
	policy.Principal.Kind = identity.Workload
	for name, c := range map[string]struct {
		s    *value.ContextSharing
		i    identity.Identity
		want error
	}{
		"missing evidence:share": {share(owner.Principal.Issuer, time.Time{}), noScope, value.ErrSharingDenied},
		"not a human":            {share(owner.Principal.Issuer, time.Time{}), policy, value.ErrSharingDenied},
		"foreign issuer":         {share("https://other.invalid", time.Time{}), owner, value.ErrInvalid},
		"end passed":             {share(owner.Principal.Issuer, now), owner, value.ErrInvalid},
		"end beyond seven days":  {share(owner.Principal.Issuer, now.Add(authorization.ShareMaxLifetime+time.Microsecond)), owner, value.ErrInvalid},
		"no recipient":           {&value.ContextSharing{}, owner, value.ErrInvalid},
	} {
		if err := previewSharing(c.s, c.i, now); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !errors.Is(value.ErrSharingDenied, value.ErrDenied) {
		t.Fatal("a sharing refusal must classify as a denial")
	}
}

type captureShares struct {
	exists bool
	err    error
}

func (c captureShares) CaptureShareExists(context.Context, string) (bool, error) {
	return c.exists, c.err
}

func TestSharingStatusIsReportedSeparately(t *testing.T) {
	ctx := context.Background()
	id := "00000000-0000-4000-8000-000000000040"
	if s, err := sharingStatus(ctx, nil, value.ContextProgressObservation{Phase: "Succeeded"}); s != nil || err != nil {
		t.Fatal("capture without instruction reported sharing", s, err)
	}
	for _, c := range []struct {
		phase  string
		exists bool
		want   string
	}{
		{"Running", false, value.SharingPending},
		{"Finalizing", false, value.SharingPending},
		{"Succeeded", true, value.SharingShared},
		{"Succeeded", false, value.SharingUnavailable},
		{"Failed", false, value.SharingUnavailable},
		{"Indeterminate", false, value.SharingUnavailable},
	} {
		s, err := sharingStatus(ctx, captureShares{exists: c.exists}, value.ContextProgressObservation{Phase: c.phase, ShareID: id})
		if err != nil || s == nil || s.State != c.want || (c.want == value.SharingShared) != (s.ShareID == id) {
			t.Errorf("%s/%v: %+v %v", c.phase, c.exists, s, err)
		}
	}
	if _, err := sharingStatus(ctx, captureShares{err: errors.New("ledger down")}, value.ContextProgressObservation{Phase: "Succeeded", ShareID: id}); !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("ledger outage reported as a sharing outcome", err)
	}
	if _, err := sharingStatus(ctx, nil, value.ContextProgressObservation{Phase: "Succeeded", ShareID: id}); !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("missing ledger reported as a sharing outcome", err)
	}
}
