package capture

import (
	"context"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// PolicyDeactivationLedger reads the policy's acceptance and clears it.
type PolicyDeactivationLedger interface {
	Status(context.Context, string) (value.PolicyStatus, error)
	DeactivatePolicy(ctx context.Context, policy, acceptance string) (replay bool, err error)
}

// PolicyDeactivation stops one accepted hub-held policy (ADR-229). The
// current human needs the team authority that sponsors activation: a current,
// undenied workload-maintainer group assignment of the policy's delegating
// AccessBinding. A permission administrator stops a policy through
// Kubernetes instead (suspending or deleting the DebugPolicy, or removing
// spec.automation), which needs no operation here. Deactivation takes effect
// at the next poll cycle and at every later capture eligibility check; it
// refunds no spend and deletes no capture or evidence.
type PolicyDeactivation struct {
	RootID, InstallationID string
	Documents              PolicyDocuments
	Ledger                 PolicyDeactivationLedger
	Permissions            PolicyPermissions
	Recovery               fleetapp.RecoveryReader
	Now                    func() time.Time
}

// PolicyDeactivationResult is response metadata, never a permit.
type PolicyDeactivationResult struct {
	PolicyUID, AcceptanceID string
	Replay                  bool
}

func (s PolicyDeactivation) Deactivate(ctx context.Context, current identities.CurrentIdentity, name string) (PolicyDeactivationResult, error) {
	var zero PolicyDeactivationResult
	if ctx == nil || current == nil || s.Documents == nil || s.Ledger == nil || s.Permissions == nil || s.Recovery == nil || s.Now == nil || !authorization.UUID(s.RootID) || !authorization.UUID(s.InstallationID) {
		return zero, value.ErrUnavailable
	}
	if !identity.Text(name, 253) {
		return zero, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) || i.Principal.Kind != identity.Human {
		return zero, value.ErrDenied
	}
	recovery, err := s.Recovery.RecoveryState(ctx)
	if err != nil || recovery.InstallationID != s.InstallationID || !recovery.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	source, _, err := s.Documents.ReadPolicy(ctx, name, "")
	if err != nil {
		return zero, value.ErrUnavailable
	}
	status, err := s.Ledger.Status(ctx, source.Revision.UID)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	acceptance := status.ActiveID
	if acceptance == "" {
		acceptance = status.DeactivatedID
	}
	if acceptance == "" {
		return zero, value.ErrUnavailable
	}
	projection, err := s.Permissions.Permissions(ctx, authorization.PolicyScope(status.Authority))
	if err != nil {
		return zero, value.ErrUnavailable
	}
	if r := authorization.PolicyStopEligibility(i, projection, status.Authority, s.Now()); !r.Eligible {
		return zero, ErrPolicyDelegation
	}
	fresh, err := current.ResolveIdentity(ctx)
	if err != nil || fresh.Principal != i.Principal || fresh.Policy != i.Policy || !fresh.Valid(s.Now()) || ctx.Err() != nil {
		return zero, value.ErrDenied
	}
	replay, err := s.Ledger.DeactivatePolicy(ctx, source.Revision.UID, acceptance)
	if err != nil {
		return zero, err
	}
	return PolicyDeactivationResult{PolicyUID: source.Revision.UID, AcceptanceID: acceptance, Replay: replay}, nil
}
