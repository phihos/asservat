package fleet

import (
	"context"
	"errors"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type fixedCurrent struct {
	identity identity.Identity
	calls    int
}

func (c *fixedCurrent) ResolveIdentity(context.Context) (identity.Identity, error) {
	c.calls++
	return c.identity, nil
}

type fixedAdministration struct{ value.Administration }

func (a fixedAdministration) FleetAdministration(context.Context) (value.Administration, error) {
	return a.Administration, nil
}

// ADR-193 step 4: each request is authorized from its own current identity
// and the fleet settings, before and after provider work; a non-operator and
// a short idempotency key are refused before any reservation.
func TestFleetBootstrapIssuanceUsesTheRequestIdentity(t *testing.T) {
	f, _, _ := newBootstrapFixture()
	now := f.now
	settings := value.Administration{InstallationID: f.a.InstallationID, IssuerEpoch: f.a.IssuerEpoch, Issuer: f.a.Actor.Issuer, Revision: identity.Revision{UID: "fleet", Generation: 1, Digest: [32]byte{2}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second),
		Clients: []string{"console"}, Groups: []string{"fleet-operators"}, DeliveryProfiles: []string{f.a.DeliveryProfile}, MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16}
	operator := &fixedCurrent{identity: identity.Identity{Principal: f.a.Actor, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{1}}, Groups: []string{"fleet-operators"}, VerifiedAt: now, ValidUntil: now.Add(10 * time.Second)}}
	service := FleetBootstrapIssuance{Settings: fixedAdministration{settings}, Reservations: f, Credentials: f, Records: f, Audits: f, Objects: f, Activation: f, Now: func() time.Time { return f.now }}
	request := FleetBootstrapRequest{DisplayName: "synthetic", Region: "eu-test", DeliveryProfile: f.a.DeliveryProfile, IdempotencyKey: "0123456789abcdef-key"}
	intent, err := service.Issue(context.Background(), operator, request)
	if err != nil || !intent.Issued || operator.calls != 2 {
		t.Fatal("operator issuance", err, operator.calls)
	}
	developer := &fixedCurrent{identity: operator.identity}
	developer.identity.Groups = []string{"developers"}
	f.credentials = 0
	if _, err = service.Issue(context.Background(), developer, request); !errors.Is(err, value.ErrDenied) || f.credentials != 0 {
		t.Fatal("non-operator reached provider work", err)
	}
	short := request
	short.IdempotencyKey = "short"
	if _, err = service.Issue(context.Background(), operator, short); !errors.Is(err, value.ErrInvalid) {
		t.Fatal("short idempotency key accepted", err)
	}
	if FleetBootstrapKeyDigest("a") == FleetBootstrapKeyDigest("b") {
		t.Fatal("idempotency keys collide")
	}
}
