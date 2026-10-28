package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

// Synthetic persistence/projections feed the real C03 and canonical browser
// route. They confer no installed, IdP, SQL, audit or execution qualification.
type consoleManagerGrants struct {
	authapp.GrantStore
	mu             sync.Mutex
	g              authorization.Grant
	revocations    int
	requests       map[string]authorization.Grant
	requestKeys    map[string]string
	requestDigests map[string]artifact.Digest
	attachment     *authorization.PolicyGrantAttachment
	attachmentKey  string
}

func (s *consoleManagerGrants) Grant(_ context.Context, id string) (authorization.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == s.g.ID {
		return s.g, nil
	}
	if g, ok := s.requests[id]; ok {
		return g, nil
	}
	return authorization.Grant{}, authapp.ErrGrantNotFound
}
func (s *consoleManagerGrants) RevokeGrant(_ context.Context, in authapp.GrantRevocationInput, _ artifact.RecoveryProof) (authorization.Grant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.GrantID != s.g.ID || in.ExpectedRevision != s.g.Revision {
		return authorization.Grant{}, false, authapp.ErrGrantConflict
	}
	s.revocations++
	s.g.Revision++
	s.g.RevokedAt = time.Now().UTC()
	s.g.Revoker = in.Revoker
	return s.g, false, nil
}
func (s *consoleManagerGrants) stats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"revocations": s.revocations, "executions_used": s.g.PolicySpend.Executions, "collected_bytes_used": s.g.PolicySpend.CollectedBytes})
}

type consoleManagerProjection struct {
	owner    artifact.AudienceAssignment
	target   authorization.WorkloadTarget
	revision identity.Revision
}

func (s consoleManagerProjection) WorkloadPermissions(context.Context, authorization.WorkloadTarget) (authorization.WorkloadProjection, error) {
	now := time.Now().UTC()
	return authorization.WorkloadProjection{Target: s.target, Revision: s.revision, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: now.Add(5 * time.Second), Allows: []authorization.CurrentAssignment{{Audience: s.owner, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}}, nil
}

type consoleManagerNoPods struct{ authapp.ProjectionReader }

func (consoleManagerNoPods) Permissions(context.Context, authorization.Target) (authorization.Projection, error) {
	panic("policy manager metadata invented a Pod")
}

type consoleManagerRecovery struct {
	root     string
	revision identity.Revision
}

func (s consoleManagerRecovery) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	now := time.Now().UTC()
	return artifact.RecoveryProof{InstallationID: s.root, IssuerEpoch: s.root, Revision: s.revision, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}

func newConsoleManagerGrants(t *testing.T, origin string) (*presentation.GrantOperations, *consoleManagerGrants) {
	t.Helper()
	now := time.Now().UTC()
	root := consoleCaptureID(700)
	rev := identity.Revision{UID: "synthetic-policy", Generation: 1, Digest: artifact.Digest{1}}
	actor := identity.Principal{Issuer: "https://identity.invalid", Subject: "departed-requester", ClientID: "console", Kind: identity.Human}
	owner := artifact.AudienceAssignment{Kind: "Group", Issuer: actor.Issuer, SubjectID: "maintainers", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "policy-manager-binding", AssignmentID: consoleCaptureID(701), BasisDigest: artifact.Digest{1}}
	scope := []byte(`{"format":"synthetic-console-policy/v1"}`)
	digest := sha256.Sum256(scope)
	authority := authorization.AcceptedPolicyAuthority{InstallationID: root, PolicyUID: "team-policy-uid", Creator: actor, Executor: authorization.PolicyPrincipal(root, "team-policy-uid"), ScopeDigest: digest, ClusterID: consoleCaptureID(1), NamespaceUID: "namespace-uid", WorkloadUID: "workload-uid", Delegation: identity.Revision{UID: owner.BasisUID, Generation: 1, Digest: artifact.Digest{1}}, Owners: []artifact.AudienceAssignment{owner}, Actions: []string{"packetCapture"}, Limits: authorization.AutomationLimits{MaxExecutions: 100, MaxBytes: 1 << 30}, IssuedAt: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour)}
	review := authapp.GrantReview{Namespace: "payments", WorkloadKind: "Deployment", WorkloadName: "api", Deadline: authority.NotAfter, Actions: []authapp.GrantReviewAction{{ActionID: "net", Kind: "packetCapture", ExecutionMode: "onTrigger", Before: "0s", After: "2s", Filter: "tcp port 80", FilterDigest: artifact.Digest{4}, FilterInstructions: 4, MaxBytes: 8 << 20, RingMaxBytes: 16 << 20, RingMaxAge: "2s", Sensitive: []string{"recordingApprovalRequired"}}}}
	body, _ := json.Marshal(review)
	g := authorization.Grant{ID: consoleCaptureID(702), RootID: root, Kind: authorization.GrantPolicy, Scope: scope, ExecutionDigest: digest, Review: body, DataClass: "extract", Reasons: []authorization.SensitiveReason{{ActionID: "net", Code: "recordingApprovalRequired"}}, Requester: actor, RequestedAt: now.Add(-time.Minute), ReviewUntil: now.Add(59 * time.Minute), Lifetime: 24 * time.Hour, Revision: 2, Policy: &authorization.PolicyGrantScope{Authority: authority, RecipeDigest: artifact.Digest{7}, Limits: authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 64 << 20}, ApprovalPolicyRef: rev, ApprovalMaxAge: 30 * 24 * time.Hour}, PolicySpend: authorization.PolicyGrantSpend{Executions: 4, CollectedBytes: 32 << 20}, PolicyNotAfter: now.Add(24*time.Hour - time.Minute)}
	g.Decision = &authorization.GrantDecision{Approved: true, Approver: identity.Principal{Issuer: actor.Issuer, Subject: "independent-reviewer", ClientID: "review-console", Kind: identity.Human}, Reason: "finite team collection", ACR: "mfa", AuthenticatedAt: now.Add(-time.Minute), DecidedAt: now.Add(-30 * time.Second)}
	g.ExpiresAt = g.PolicyNotAfter
	g.ReviewDigest = authapp.ReviewDigest(g, g.Review)
	if !g.Valid() {
		t.Fatal("invalid synthetic policy grant")
	}
	store := &consoleManagerGrants{g: g}
	service := authapp.GrantService{RootID: root, InstallationID: root, Permissions: consoleManagerNoPods{}, WorkloadPermissions: consoleManagerProjection{owner, g.Policy.Workload(), rev}, Store: store, Recovery: consoleManagerRecovery{root, rev}, Now: time.Now, NewID: func() string { return consoleCaptureID(703) }}
	service.PolicyRequests = store
	service.PolicyPlans = consolePolicyGrantPlan{store}
	service.ApprovalSettings = consolePolicyGrantSettings{store}
	service.NewID = func() string { return consoleCaptureID(706) }
	wire, err := presentation.NewGrantOperations(origin, time.Now, service.NewID, service)
	if err != nil {
		t.Fatal(err)
	}
	return wire, store
}

// Real C03 request workflow with synthetic accepted-plan/settings persistence;
// the source compiler and protected settings producers have separate tests.
type consolePolicyGrantPlan struct{ store *consoleManagerGrants }

func (s consolePolicyGrantPlan) PolicyGrantPlan(_ context.Context, uid, name string) (authapp.PolicyGrantPlan, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	g := s.store.g
	if uid != g.Policy.Authority.PolicyUID || name != "team-policy" {
		return authapp.PolicyGrantPlan{}, authapp.ErrGrantUnavailable
	}
	var review authapp.GrantReview
	if json.Unmarshal(g.Review, &review) != nil {
		return authapp.PolicyGrantPlan{}, authapp.ErrGrantUnavailable
	}
	return authapp.PolicyGrantPlan{Authority: g.Policy.Authority, RecipeDigest: g.Policy.RecipeDigest, Scope: bytes.Clone(g.Scope), Review: review, DataClass: g.DataClass, Reasons: append([]authorization.SensitiveReason(nil), g.Reasons...), FreshUntil: time.Now().Add(5 * time.Second)}, nil
}

type consolePolicyGrantSettings struct{ store *consoleManagerGrants }

func (s consolePolicyGrantSettings) PolicyApprovalSettings(context.Context) (authapp.AcceptedPolicyApprovalSettings, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	now := time.Now()
	return authapp.AcceptedPolicyApprovalSettings{Values: authorization.PolicyApprovalSettings{DefaultAge: 7 * 24 * time.Hour, MaxAge: 30 * 24 * time.Hour, RenewalNotice: 24 * time.Hour}, Revision: s.store.g.Policy.ApprovalPolicyRef, ObservedAt: now, FreshUntil: now.Add(30 * time.Second)}, nil
}
func consolePolicyRequestKey(actor identity.Principal, uid, key string) string {
	b, _ := json.Marshal(struct {
		Actor    identity.Principal
		UID, Key string
	}{actor, uid, key})
	return string(b)
}
func (s *consoleManagerGrants) LookupPolicyGrantRequest(_ context.Context, in authapp.PolicyGrantRequestLookup) (authorization.Grant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := consolePolicyRequestKey(in.Requester, in.PolicyUID, in.IdempotencyKey)
	id, found := s.requestKeys[key]
	if !found {
		return authorization.Grant{}, false, nil
	}
	if s.requestDigests[key] != in.InputDigest {
		return authorization.Grant{}, false, authapp.ErrGrantConflict
	}
	return s.requests[id], true, nil
}
func (s *consoleManagerGrants) RequestGrant(_ context.Context, in authapp.StoredGrantRequest, _ artifact.RecoveryProof) (authorization.Grant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := in.Grant
	key := consolePolicyRequestKey(g.Requester, g.Policy.Authority.PolicyUID, in.IdempotencyKey)
	if id, found := s.requestKeys[key]; found {
		if s.requestDigests[key] != in.RequestDigest {
			return authorization.Grant{}, false, authapp.ErrGrantConflict
		}
		return s.requests[id], true, nil
	}
	now := time.Now().UTC()
	g.RequestedAt = now
	g.ReviewUntil = now.Add(authorization.GrantReviewWindow)
	g.PolicyNotAfter = identity.Earlier(now.Add(g.Lifetime), g.Policy.Authority.NotAfter)
	if !g.Valid() {
		return authorization.Grant{}, false, authorization.ErrGrantInvalid
	}
	if s.requests == nil {
		s.requests = map[string]authorization.Grant{}
		s.requestKeys = map[string]string{}
		s.requestDigests = map[string]artifact.Digest{}
	}
	s.requests[g.ID] = g
	s.requestKeys[key] = g.ID
	s.requestDigests[key] = in.RequestDigest
	return g, false, nil
}
