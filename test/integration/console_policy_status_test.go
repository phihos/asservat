package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
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

func (s consolePolicyStatus) ReadPolicy(_ context.Context, name, uid string) (value.PolicySource, []byte, error) {
	s.grants.mu.Lock()
	defer s.grants.mu.Unlock()
	a := s.grants.g.Policy.Authority
	if name != "team-policy" || uid != "" && uid != a.PolicyUID {
		return value.PolicySource{}, nil, value.ErrUnavailable
	}
	now := time.Now().UTC()
	return value.PolicySource{InstallationID: a.InstallationID, ClusterID: a.ClusterID, NamespaceUID: "control-namespace-uid", Name: name, Revision: identity.Revision{UID: a.PolicyUID, Generation: 1, Digest: artifact.Digest{1}}, ResourceVersion: "fixture-policy-v1", CollectionDigest: artifact.Digest{2}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil, nil
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
	activation := app.PolicyActivation{RootID: grants.g.RootID, InstallationID: grants.g.RootID, Documents: f, Sources: f, Ledger: f, GrantAttachments: f, Recovery: f, Now: time.Now}
	operations, err := presentation.NewPolicyOperations(origin, time.Now, func() string { return consoleCaptureID(704) }, activation, service, f)
	if err != nil {
		t.Fatal(err)
	}
	return operations
}

func (s consolePolicyStatus) ObservePolicy(context.Context, value.PolicySource) error { return nil }
func (s consolePolicyStatus) Delegation(context.Context, authorization.Target) (identity.Revision, error) {
	return identity.Revision{}, value.ErrUnavailable
}
func (s consolePolicyStatus) ActiveClusterPolicies(context.Context, string, string) (int64, error) {
	return 0, value.ErrUnavailable
}
func (s consolePolicyStatus) AcceptanceByNonce(context.Context, string) (value.PolicyAcceptance, bool, error) {
	return value.PolicyAcceptance{}, false, value.ErrUnavailable
}
func (s consolePolicyStatus) AttachPolicyGrant(ctx context.Context, in authapp.PolicyGrantAttachmentInput) (authorization.PolicyGrantAttachment, bool, error) {
	s.grants.mu.Lock()
	defer s.grants.mu.Unlock()
	g := s.grants.g
	a := g.Policy.Authority
	now := time.Now()
	projection, err := (consoleManagerProjection{a.Owners[0], g.Policy.Workload(), g.Policy.ApprovalPolicyRef}).WorkloadPermissions(ctx, g.Policy.Workload())
	now = time.Now()
	if err != nil || !authorization.PolicyGrantManagementEligibility(in.Actor, projection, a, now).Eligible || in.PolicyUID != a.PolicyUID {
		return authorization.PolicyGrantAttachment{}, false, value.ErrDenied
	}
	if s.grants.attachment != nil && s.grants.attachmentKey == in.IdempotencyKey {
		old := *s.grants.attachment
		if old.Actor != in.Actor.Principal || old.GrantID != in.GrantID {
			return authorization.PolicyGrantAttachment{}, false, value.ErrConflict
		}
		return old, true, nil
	}
	if in.GrantID != g.ID {
		return authorization.PolicyGrantAttachment{}, false, value.ErrDenied
	}
	if err = authorization.CheckPolicyGrantAttachment(g, a, "", now); err != nil {
		return authorization.PolicyGrantAttachment{}, false, err
	}
	receipt := authorization.PolicyGrantAttachment{ID: in.ID, RootID: g.RootID, InstallationID: g.RootID, PolicyUID: a.PolicyUID, AcceptanceID: consoleCaptureID(703), GrantID: g.ID, AuthorityDigest: a.ScopeDigest, Actor: in.Actor.Principal, AttachedAt: now}
	s.grants.attachment = &receipt
	s.grants.attachmentKey = in.IdempotencyKey
	return receipt, false, nil
}

func TestConsolePolicyAttachmentRoutePreservesCoherentSourceAndOriginalBounds(t *testing.T) {
	_, grants := newConsoleManagerGrants(t, "https://asservat.example.invalid")
	now := time.Now()
	current := &publicPolicyIdentity{i: identity.Identity{Principal: identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic-developer", ClientID: "console", Kind: identity.Human}, Policy: grants.g.Policy.ApprovalPolicyRef, Groups: []string{"maintainers"}, Scopes: []string{"evidence:read", "evidence:capture"}, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}}
	source, _, err := (consolePolicyStatus{grants: grants}).ReadPolicy(context.Background(), "team-policy", "")
	if err != nil || !source.Valid(time.Now()) {
		t.Fatal("invalid explicit fixture source", err)
	}
	operations := newConsolePolicyStatus(t, "https://asservat.example.invalid", grants)
	body := []byte(`{"policy_name":"team-policy","grant_id":"00000000-0000-4000-8000-000000000702","idempotency_key":"fixture-attach"}`)
	reply, err := operations.Call(context.Background(), current, "activate_policy", body)
	if err != nil {
		t.Fatal(err)
	}
	var result struct{ Status string }
	if json.Unmarshal(reply.Body, &result) != nil || result.Status != "ok" {
		t.Fatal("full attachment route refused coherent fixture", string(reply.Body))
	}
	if grants.attachment == nil || grants.attachment.GrantID != grants.g.ID || grants.g.PolicySpend.Executions != 4 || grants.g.PolicySpend.CollectedBytes != 32<<20 {
		t.Fatal("control changed reservation or failed to attach")
	}
}
