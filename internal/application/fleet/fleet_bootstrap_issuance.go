package fleet

import (
	"context"
	"crypto/sha256"
	"time"

	auditport "asservat.local/asservat/internal/application/audit"
	identityport "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// FleetBootstrapIssuance is the hub-api fleet-operator operation (ADR-193
// step 4). Each request is authorized from its own current identity and the
// protected fleet settings; the audited BootstrapIssuer does the rest.
type FleetBootstrapIssuance struct {
	Settings     AdministrationReader
	Reservations BootstrapReservations
	Credentials  BootstrapCredentials
	Records      BootstrapCredentialRecorder
	Audits       auditport.BootstrapIssueLedger
	Objects      auditport.BootstrapIssueWriter
	Activation   BootstrapActivator
	Now          func() time.Time
}

// FleetBootstrapRequest carries only operator-chosen display values, the
// configured delivery profile name and the client's idempotency key.
type FleetBootstrapRequest struct {
	DisplayName, Region, DeliveryProfile, IdempotencyKey string
}

// currentResolver answers the authorizer from the request's own current
// identity; the token argument is unused because the session resolved it.
type currentResolver struct{ current identityport.CurrentIdentity }

func (r currentResolver) Resolve(ctx context.Context, _ string) (identity.Identity, error) {
	return r.current.ResolveIdentity(ctx)
}

func (s FleetBootstrapIssuance) Issue(ctx context.Context, current identityport.CurrentIdentity, r FleetBootstrapRequest) (value.BootstrapIntent, error) {
	if current == nil || s.Settings == nil || s.Now == nil {
		return value.BootstrapIntent{}, value.ErrUnavailable
	}
	if !identity.Text(r.IdempotencyKey, 128) || len(r.IdempotencyKey) < 16 {
		return value.BootstrapIntent{}, value.ErrInvalid
	}
	issuer := BootstrapIssuer{Authority: EnrollmentAuthorizer{Identities: currentResolver{current}, Settings: s.Settings, Now: s.Now},
		Reservations: s.Reservations, Credentials: s.Credentials, Records: s.Records, Audits: s.Audits, Objects: s.Objects, Activation: s.Activation, Now: s.Now}
	return issuer.Issue(ctx, "", BootstrapInput{KeyDigest: FleetBootstrapKeyDigest(r.IdempotencyKey), DisplayName: r.DisplayName, Region: r.Region, DeliveryProfile: r.DeliveryProfile})
}

// FleetBootstrapKeyDigest separates the idempotency key's hash domain; the
// reservation pairs it with the actor digest, so keys never cross operators.
func FleetBootstrapKeyDigest(key string) artifact.Digest {
	return sha256.Sum256(append([]byte("asservat-fleet-bootstrap-request/v1\x00"), key...))
}
