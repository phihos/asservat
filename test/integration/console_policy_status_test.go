package integration

import (
	"context"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

// Only synthetic persistence/source/projection facts; the ordinary status
// service and canonical HTTPS/browser route perform real viewer authorization.
type consolePolicyStatus struct{ grants *consoleManagerGrants }

func (s consolePolicyStatus) ReadPolicy(context.Context, string, string) (value.PolicySource, []byte, error) {
	return value.PolicySource{Revision: identity.Revision{UID: "team-policy-uid", Generation: 1, Digest: artifact.Digest{1}}}, nil, nil
}
func (s consolePolicyStatus) Status(context.Context, string) (value.PolicyStatus, error) {
	s.grants.mu.Lock()
	defer s.grants.mu.Unlock()
	a := s.grants.g.Policy.Authority
	return value.PolicyStatus{PolicyUID: a.PolicyUID, ActiveID: consoleCaptureID(703), Generation: 1, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, Authority: a, NotAfter: a.NotAfter, ExecutionsSpent: 5, MaxExecutions: a.Limits.MaxExecutions, CollectedBytesSpent: 16384, MaxCollectedBytes: a.Limits.MaxBytes, ObservedBytesSpent: 0, MaxObservedBytes: a.Limits.MaxObservedBytes, SourceObservedAt: time.Now(), SourceFreshUntil: time.Now().Add(5 * time.Second)}, nil
}
func (s consolePolicyStatus) Permissions(_ context.Context, target authorization.Target) (authorization.Projection, error) {
	s.grants.mu.Lock()
	defer s.grants.mu.Unlock()
	now := time.Now()
	return authorization.Projection{Target: target, Revision: s.grants.g.Policy.ApprovalPolicyRef, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: now.Add(5 * time.Second), Allows: []authorization.CurrentAssignment{{Audience: s.grants.g.Policy.Authority.Owners[0], ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}}, nil
}
func (s consolePolicyStatus) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	s.grants.mu.Lock()
	defer s.grants.mu.Unlock()
	now := time.Now()
	return artifact.RecoveryProof{InstallationID: s.grants.g.RootID, IssuerEpoch: s.grants.g.RootID, Revision: s.grants.g.Policy.ApprovalPolicyRef, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}
func (s consolePolicyStatus) Activate(context.Context, identities.CurrentIdentity, string, string, bool) (app.PolicyActivationResult, error) {
	return app.PolicyActivationResult{}, value.ErrUnavailable
}
func (s consolePolicyStatus) Deactivate(context.Context, identities.CurrentIdentity, string) (app.PolicyDeactivationResult, error) {
	return app.PolicyDeactivationResult{}, value.ErrUnavailable
}
func newConsolePolicyStatus(t *testing.T, origin string, grants *consoleManagerGrants) *presentation.PolicyOperations {
	t.Helper()
	f := consolePolicyStatus{grants: grants}
	service := app.PolicyStatusService{RootID: grants.g.RootID, InstallationID: grants.g.RootID, Documents: f, Ledger: f, Permissions: f, Recovery: f, Now: time.Now}
	operations, err := presentation.NewPolicyOperations(origin, time.Now, func() string { return consoleCaptureID(704) }, f, service, f)
	if err != nil {
		t.Fatal(err)
	}
	return operations
}
