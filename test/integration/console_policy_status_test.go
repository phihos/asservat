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
type consolePolicyStatus struct {
	grants *consoleManagerGrants
	spec   []byte
}

func (s consolePolicyStatus) ReadPolicy(_ context.Context, name, uid string) (value.PolicySource, []byte, error) {
	s.grants.mu.Lock()
	defer s.grants.mu.Unlock()
	a := s.grants.g.Policy.Authority
	if name != "team-policy" || uid != "" && uid != a.PolicyUID {
		return value.PolicySource{}, nil, value.ErrUnavailable
	}
	now := time.Now().UTC()
	return value.PolicySource{InstallationID: a.InstallationID, ClusterID: a.ClusterID, NamespaceUID: "control-namespace-uid", Name: name, Revision: identity.Revision{UID: a.PolicyUID, Generation: 1, Digest: artifact.Digest{1}}, ResourceVersion: "fixture-policy-v1", CollectionDigest: artifact.Digest{2}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, s.spec, nil
}

func (s consolePolicyStatus) Status(context.Context, string) (value.PolicyStatus, error) {
	s.grants.mu.Lock()
	defer s.grants.mu.Unlock()
	a := s.grants.g.Policy.Authority
	attached := ""
	if s.grants.attachment != nil {
		attached = s.grants.attachment.GrantID
	}
	return value.PolicyStatus{AttachedGrantID: attached, PolicyUID: a.PolicyUID, ActiveID: consoleCaptureID(703), Generation: 1, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, Authority: a, NotAfter: a.NotAfter, ExecutionsSpent: 5, MaxExecutions: a.Limits.MaxExecutions, CollectedBytesSpent: 16384, MaxCollectedBytes: a.Limits.MaxBytes, ObservedBytesSpent: 0, MaxObservedBytes: a.Limits.MaxObservedBytes, SourceObservedAt: time.Now(), SourceFreshUntil: time.Now().Add(5 * time.Second)}, nil
}
func (s consolePolicyStatus) Permissions(_ context.Context, target authorization.Target) (authorization.Projection, error) {
	s.grants.mu.Lock()
	defer s.grants.mu.Unlock()
	now := time.Now()
	return authorization.Projection{Target: target, Revision: s.grants.g.Policy.ApprovalPolicyRef, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: now.Add(5 * time.Second), Allows: []authorization.CurrentAssignment{{Audience: s.grants.g.Policy.Authority.Owners[0], ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}}, nil
}
func (s consolePolicyStatus) Deactivate(context.Context, identities.CurrentIdentity, string, string, string) (app.PolicyDeactivationResult, error) {
	return app.PolicyDeactivationResult{}, value.ErrUnavailable
}
func newConsolePolicyStatus(t *testing.T, origin string, grants *consoleManagerGrants) *presentation.PolicyOperations {
	t.Helper()
	// The policy targets namespace "app" of the hub's own cluster ("local").
	f := consolePolicyStatus{grants: grants, spec: publicPolicySpec(t, grants.g.Policy.Authority)}
	service := app.PolicyStatusService{RootID: grants.g.RootID, InstallationID: grants.g.RootID, Documents: f, Ledger: f, Permissions: f, Now: time.Now}
	clusters := presentation.NewClusterNames(map[string]string{presentation.LocalClusterName: grants.g.Policy.Authority.ClusterID})
	operations, err := presentation.NewPolicyOperations(origin, time.Now, func() string { return consoleCaptureID(704) }, clusters, service, f)
	if err != nil {
		t.Fatal(err)
	}
	return operations
}
