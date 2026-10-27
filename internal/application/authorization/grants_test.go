package authorization

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// memoryGrants mirrors the SQL ledger's rules (migration 00097) closely
// enough to exercise the service: one request per capture, one decision by a
// distinct human, one revocation, monotonic pool spend and idempotent keys.
type memoryGrants struct {
	mu       sync.Mutex
	now      func() time.Time
	rows     map[string]value.Grant
	keys     map[string]string
	children map[string]value.GrantChild
	uses     map[string]GrantUseRequest
	decided  map[string]string
	revoked  map[string]string
	locator  map[string]string // artifact -> capture (published)
}

func newMemoryGrants(now func() time.Time) *memoryGrants {
	return &memoryGrants{now: now, rows: map[string]value.Grant{}, keys: map[string]string{}, children: map[string]value.GrantChild{}, uses: map[string]GrantUseRequest{}, decided: map[string]string{}, revoked: map[string]string{}, locator: map[string]string{}}
}

func (m *memoryGrants) RequestGrant(_ context.Context, r StoredGrantRequest, _ artifact.RecoveryProof) (value.Grant, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := r.Grant.Requester.Issuer + "\n" + r.Grant.Requester.Subject + "\n" + r.IdempotencyKey
	if id, ok := m.keys[k]; ok {
		return m.rows[id], true, nil
	}
	for _, g := range m.rows {
		if g.CaptureID == r.Grant.CaptureID {
			return value.Grant{}, false, ErrGrantConflict
		}
	}
	g := r.Grant
	g.RequestedAt = m.now()
	g.ReviewUntil = g.RequestedAt.Add(value.GrantReviewWindow)
	if !g.Valid() {
		return value.Grant{}, false, value.ErrGrantInvalid
	}
	m.rows[g.ID], m.keys[k] = g, g.ID
	return g, false, nil
}

func (m *memoryGrants) Grant(_ context.Context, id string) (value.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.rows[id]
	if !ok {
		return value.Grant{}, ErrGrantNotFound
	}
	return g, nil
}

func (m *memoryGrants) GrantByCapture(_ context.Context, capture string) (value.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, g := range m.rows {
		if g.CaptureID == capture {
			return g, nil
		}
	}
	return value.Grant{}, ErrGrantNotFound
}

func (m *memoryGrants) PendingGrants(context.Context, int) ([]value.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []value.Grant
	for _, g := range m.rows {
		if g.Phase(m.now()) == value.GrantPending {
			out = append(out, g)
		}
	}
	return out, nil
}

func (m *memoryGrants) RequestedGrants(_ context.Context, p identity.Principal, _ int) ([]value.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []value.Grant
	for _, g := range m.rows {
		if g.Requester.Issuer == p.Issuer && g.Requester.Subject == p.Subject {
			out = append(out, g)
		}
	}
	return out, nil
}

func (m *memoryGrants) DecideGrant(_ context.Context, in GrantDecisionInput, _ artifact.RecoveryProof) (value.Grant, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.rows[in.GrantID]
	if !ok {
		return value.Grant{}, false, ErrGrantNotFound
	}
	if g.Decision != nil {
		if m.decided[g.ID] == in.IdempotencyKey && g.Decision.Approver == in.Approver && g.Decision.Approved == in.Approve {
			return g, true, nil
		}
		return value.Grant{}, false, value.ErrGrantNotPending
	}
	if sameHuman(g.Requester, in.Approver) {
		return value.Grant{}, false, value.ErrSelfApproval
	}
	now := m.now()
	if !g.RevokedAt.IsZero() || !now.Before(g.ReviewUntil) {
		return value.Grant{}, false, value.ErrGrantNotPending
	}
	g.Decision = &value.GrantDecision{Approved: in.Approve, Approver: in.Approver, Reason: in.Reason, ACR: in.ACR, AuthenticatedAt: in.AuthTime, DecidedAt: now}
	if in.Approve {
		g.ExpiresAt = now.Add(g.Lifetime)
		if g.ResultAccess != nil {
			g.ExpiresAt = identity.Earlier(g.ExpiresAt, g.ResultAccess.NotAfter)
		}
	}
	g.Revision++
	if !g.Valid() {
		return value.Grant{}, false, value.ErrGrantInvalid
	}
	m.rows[g.ID], m.decided[g.ID] = g, in.IdempotencyKey
	return g, false, nil
}

func (m *memoryGrants) RevokeGrant(_ context.Context, in GrantRevocationInput, _ artifact.RecoveryProof) (value.Grant, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.rows[in.GrantID]
	if !ok {
		return value.Grant{}, false, ErrGrantNotFound
	}
	if !g.RevokedAt.IsZero() {
		if m.revoked[g.ID] == in.IdempotencyKey && sameHuman(g.Revoker, in.Revoker) {
			return g, true, nil
		}
		return value.Grant{}, false, value.ErrGrantRevoked
	}
	if g.Revision != in.ExpectedRevision {
		return value.Grant{}, false, ErrGrantConflict
	}
	g.RevokedAt, g.Revoker = m.now(), in.Revoker
	g.Revision++
	m.rows[g.ID], m.revoked[g.ID] = g, in.IdempotencyKey
	return g, false, nil
}

func (m *memoryGrants) MaterializeGrantChild(_ context.Context, in GrantChildRequest, _ artifact.RecoveryProof) (value.GrantChild, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.rows[in.ParentID]
	if !ok {
		return value.GrantChild{}, false, ErrGrantNotFound
	}
	registered := false
	for _, c := range m.children {
		if c.ParentID == in.ParentID && c.Output.ArtifactID == in.Output.ArtifactID {
			registered = true
			if c.ClientID == in.ClientID {
				if err := value.CheckMaterialize(g, in.Output, in.ClientID, true, m.now()); err != nil {
					return value.GrantChild{}, false, err
				}
				return c, true, nil
			}
		}
	}
	if err := value.CheckMaterialize(g, in.Output, in.ClientID, registered, m.now()); err != nil {
		return value.GrantChild{}, false, err
	}
	if m.locator[in.Output.ArtifactID] != g.CaptureID {
		return value.GrantChild{}, false, value.ErrGrantScope
	}
	if !registered {
		g.Spent.Artifacts++
		m.rows[g.ID] = g
	}
	c := value.GrantChild{ID: in.ChildID, ParentID: in.ParentID, ClientID: in.ClientID, Output: in.Output, CreatedAt: m.now()}
	m.children[c.ID] = c
	return c, false, nil
}

func (m *memoryGrants) GrantChild(_ context.Context, id string) (value.GrantChild, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.children[id]
	if !ok {
		return value.GrantChild{}, ErrGrantNotFound
	}
	return c, nil
}

func (m *memoryGrants) ReserveGrantUse(_ context.Context, in GrantUseRequest, _ artifact.RecoveryProof) (value.Grant, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.rows[in.ParentID]
	if prior, ok := m.uses[in.UseID]; ok {
		if prior != in {
			return value.Grant{}, false, ErrGrantConflict
		}
		return g, true, nil
	}
	if p := g.Phase(m.now()); p != value.GrantApproved {
		return value.Grant{}, false, value.ErrGrantRevoked
	}
	r := g.ResultAccess
	if !value.PoolCovers(g, in.Use) || r == nil {
		return value.Grant{}, false, value.ErrGrantPoolExhausted
	}
	g.Spent.Bytes += in.Use.Bytes
	g.Spent.Operations += in.Use.Operations
	m.rows[g.ID], m.uses[in.UseID] = g, in
	return g, false, nil
}

// grantIdentity is one current observation of a fixed principal at the
// fixture's clock (assurance keeps its absolute times).
type grantIdentity struct {
	i   identity.Identity
	now *time.Time
}

func (g grantIdentity) ResolveIdentity(context.Context) (identity.Identity, error) {
	i := g.i
	if g.now != nil {
		i.VerifiedAt, i.ValidUntil = *g.now, g.now.Add(30*time.Second)
	}
	return i, nil
}

type grantFixture struct {
	now                          time.Time
	store                        *memoryGrants
	svc                          GrantService
	target                       value.Target
	requester, approver, outside identity.Identity
	ids                          int
	projection                   func(value.Target) value.Projection
}

const grantRoot = "11111111-2222-4333-8444-555555555555"

func grantID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func newGrantFixture(t *testing.T) *grantFixture {
	t.Helper()
	f := &grantFixture{now: time.Now().UTC().Truncate(time.Microsecond)}
	f.store = newMemoryGrants(func() time.Time { return f.now })
	f.target = value.Target{ClusterID: grantID(1), NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod"}
	rev := identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{1}}
	human := func(subject, client string, scopes ...string) identity.Identity {
		return identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: subject, ClientID: client, Kind: identity.Human}, Scopes: append([]string{"evidence:read"}, scopes...), Groups: []string{subject + "-team"}, Policy: rev, VerifiedAt: f.now, ValidUntil: f.now.Add(30 * time.Second)}
	}
	f.requester = human("dev", "console", "evidence:capture", "evidence:download")
	f.approver = human("lead", "console")
	f.approver.Assurance = identity.Assurance{ACR: "mfa", AuthenticatedAt: f.now.Add(-time.Minute), StepUpUntil: f.now.Add(4 * time.Minute)}
	f.outside = human("other", "console", "evidence:capture")
	assign := func(subject, role string, n int) value.CurrentAssignment {
		return value.CurrentAssignment{Audience: artifact.AudienceAssignment{Kind: "User", Issuer: f.requester.Principal.Issuer, SubjectID: subject, Role: role, BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: grantID(900 + n), BasisDigest: artifact.Digest{byte(n)}}, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second)}
	}
	f.projection = func(t value.Target) value.Projection {
		return value.Projection{Target: t, Revision: rev, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: f.now, DeniesFreshUntil: f.now.Add(30 * time.Second),
			Allows: []value.CurrentAssignment{assign("dev", "workload-maintainer", 1), assign("lead", "action-approver", 2), assign("other", "workload-maintainer", 3)}}
	}
	recovery := artifact.RecoveryProof{InstallationID: grantRoot, IssuerEpoch: grantRoot, Revision: rev, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}
	f.svc = GrantService{RootID: grantRoot, InstallationID: grantRoot, Permissions: projectionFunc(func(t value.Target) value.Projection { return f.projection(t) }), Store: f.store,
		Recovery: recoveryFunc(func() artifact.RecoveryProof {
			recovery.ObservedAt, recovery.FreshUntil = f.now, f.now.Add(5*time.Second)
			return recovery
		}),
		NewID: func() string { f.ids++; return grantID(100 + f.ids) }, Now: func() time.Time { return f.now }}
	return f
}

type projectionFunc func(value.Target) value.Projection

func (p projectionFunc) Permissions(_ context.Context, t value.Target) (value.Projection, error) {
	return p(t), nil
}

type recoveryFunc func() artifact.RecoveryProof

func (r recoveryFunc) RecoveryState(context.Context) (artifact.RecoveryProof, error) { return r(), nil }

var grantScope = []byte(`{"schemaVersion":"recorder-preview/v1"}`)

func (f *grantFixture) input(capture int, access *value.ResultAccess) GrantRequestInput {
	return GrantRequestInput{PreviewID: grantID(capture + 1000), CaptureID: grantID(capture), Actor: f.requester.Principal, Target: f.target, Scope: grantScope, ExecutionDigest: sha256.Sum256(grantScope), DataClass: "extract",
		Reasons: []value.SensitiveReason{{ActionID: "a1", Code: "rawBytePredicate"}}, Review: GrantReview{Namespace: "payments", WorkloadKind: "Deployment", WorkloadName: "api", PodName: "api-a", Actions: []GrantReviewAction{{ActionID: "a1", Kind: "packetCapture"}}, Deadline: f.now.Add(5 * time.Minute)},
		Lifetime: value.GrantDefaultLifetime, ResultAccess: access, IdempotencyKey: fmt.Sprintf("key-%d", capture)}
}

func (f *grantFixture) access() *value.ResultAccess {
	return &value.ResultAccess{ActionIDs: []string{"a1"}, Operations: []string{value.GrantDownloadOperation}, ClientIDs: []string{"console", "agent"}, MaxArtifacts: 1, MaxBytes: 100, MaxOperations: 3, NotAfter: f.now.Add(2 * time.Hour)}
}

func (f *grantFixture) request(t *testing.T, capture int, access *value.ResultAccess) value.Grant {
	t.Helper()
	g, _, err := f.svc.Request(context.Background(), grantIdentity{f.requester, &f.now}, f.input(capture, access))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func (f *grantFixture) approve(t *testing.T, g value.Grant) value.Grant {
	t.Helper()
	out, _, err := f.svc.Decide(context.Background(), grantIdentity{f.approver, &f.now}, g.ID, true, "incident 42", "decide-"+g.ID)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The ADR-249 evaluator matrix through the service: self-approval refused
// across clients, step-up, non-approvers, expiry, revocation and digest
// mismatch, with the requester's current eligibility at every use.
func TestGrantDecisionAndCoveringMatrix(t *testing.T) {
	ctx := context.Background()
	f := newGrantFixture(t)
	g := f.request(t, 1, nil)
	if g.Phase(f.now) != value.GrantPending || g.Revision != 1 || ReviewDigest(g, g.Review) != g.ReviewDigest {
		t.Fatalf("pending request %+v", g)
	}
	if _, _, err := f.svc.Covering(ctx, grantIdentity{f.requester, &f.now}, g.CaptureID, g.ExecutionDigest, f.target); !errors.Is(err, value.ErrApprovalRequired) {
		t.Fatal("pending request covers", err)
	}
	// Self-approval: the requester through another client, even stepped up
	// and holding the approver role, is refused.
	self := f.requester
	self.Principal.ClientID = "other-browser"
	self.Assurance = f.approver.Assurance
	lead := f.projection
	f.projection = func(t value.Target) value.Projection {
		p := lead(t)
		a := p.Allows[1]
		a.Audience.SubjectID, a.Audience.AssignmentID = "dev", grantID(950)
		p.Allows = append(p.Allows, a)
		return p
	}
	if _, _, err := f.svc.Decide(ctx, grantIdentity{self, &f.now}, g.ID, true, "self", "self-1"); !errors.Is(err, value.ErrSelfApproval) {
		t.Fatal("self-approval", err)
	}
	if f.store.rows[g.ID].Decision != nil || len(f.store.decided) != 0 {
		t.Fatal("immutable self-refusal mutated grant ledger")
	}
	f.projection = lead
	// A distinct human without the approver role, and an approver without a
	// current step-up, are refused; denial needs no step-up.
	if _, _, err := f.svc.Decide(ctx, grantIdentity{f.outside, &f.now}, g.ID, true, "x", "x-1"); !errors.Is(err, value.ErrNotApprover) {
		t.Fatal("non-approver", err)
	}
	plain := f.approver
	plain.Assurance = identity.Assurance{}
	if _, _, err := f.svc.Decide(ctx, grantIdentity{plain, &f.now}, g.ID, true, "x", "x-2"); !errors.Is(err, value.ErrStepUpRequired) {
		t.Fatal("step-up", err)
	}
	stale := f.approver
	stale.Assurance.StepUpUntil = f.now
	if _, _, err := f.svc.Decide(ctx, grantIdentity{stale, &f.now}, g.ID, true, "x", "x-3"); !errors.Is(err, value.ErrStepUpRequired) {
		t.Fatal("expired step-up", err)
	}
	approved := f.approve(t, g)
	if approved.Phase(f.now) != value.GrantApproved || approved.Revision != 2 || approved.Decision.ACR != "mfa" || !approved.ExpiresAt.Equal(f.now.Add(time.Hour)) {
		t.Fatalf("approval %+v", approved.Decision)
	}
	// Idempotent retry; a second decision is not pending.
	if again, replay, err := f.svc.Decide(ctx, grantIdentity{f.approver, &f.now}, g.ID, true, "incident 42", "decide-"+g.ID); err != nil || !replay || again.Revision != 2 {
		t.Fatal("decision replay", err)
	}
	if _, _, err := f.svc.Decide(ctx, grantIdentity{f.approver, &f.now}, g.ID, false, "changed my mind", "other-key"); !errors.Is(err, value.ErrGrantNotPending) {
		t.Fatal("second decision", err)
	}
	if _, _, err := f.svc.Covering(ctx, grantIdentity{f.requester, &f.now}, g.CaptureID, g.ExecutionDigest, f.target); err != nil {
		t.Fatal("approved grant does not cover", err)
	}
	// Scope digest mismatch, another capture, another requester and another
	// target never use it.
	if _, _, err := f.svc.Covering(ctx, grantIdentity{f.requester, &f.now}, g.CaptureID, artifact.Digest{9}, f.target); !errors.Is(err, value.ErrGrantScope) {
		t.Fatal("execution digest mismatch", err)
	}
	if _, _, err := f.svc.Covering(ctx, grantIdentity{f.outside, &f.now}, g.CaptureID, g.ExecutionDigest, f.target); !errors.Is(err, value.ErrGrantPrincipal) {
		t.Fatal("another requester", err)
	}
	other := f.target
	other.PodUID = "replacement"
	if _, _, err := f.svc.Covering(ctx, grantIdentity{f.requester, &f.now}, g.CaptureID, g.ExecutionDigest, other); !errors.Is(err, value.ErrGrantScope) {
		t.Fatal("replacement pod", err)
	}
	// Current entitlement wins: a deny on the requester stops the use.
	f.projection = func(t value.Target) value.Projection {
		p := lead(t)
		p.Denies = []value.CurrentAssignment{p.Allows[0]}
		return p
	}
	if _, _, err := f.svc.Covering(ctx, grantIdentity{f.requester, &f.now}, g.CaptureID, g.ExecutionDigest, f.target); !errors.Is(err, identity.ErrDenied) {
		t.Fatal("deny ignored", err)
	}
	f.projection = lead
	// A tampered stored row (review digest) is refused.
	tampered := f.store.rows[g.ID]
	tampered.DataClass = "metadata"
	f.store.rows[g.ID] = tampered
	if _, _, err := f.svc.Covering(ctx, grantIdentity{f.requester, &f.now}, g.CaptureID, g.ExecutionDigest, f.target); !errors.Is(err, value.ErrGrantScope) {
		t.Fatal("tampered row", err)
	}
	tampered.DataClass = "extract"
	f.store.rows[g.ID] = tampered
	// Expiry.
	f.now = approved.ExpiresAt
	if _, _, err := f.svc.Covering(ctx, grantIdentity{f.requester, &f.now}, g.CaptureID, g.ExecutionDigest, f.target); !errors.Is(err, value.ErrGrantExpired) {
		t.Fatal("expired grant covers", err)
	}
}

func TestGrantRevocationDenialAndVisibility(t *testing.T) {
	ctx := context.Background()
	f := newGrantFixture(t)
	g := f.request(t, 2, nil)
	// Outsiders see nothing; the approver inbox lists it; the requester's
	// own list includes it but the inbox does not.
	if _, _, err := f.svc.Get(ctx, grantIdentity{f.outside, &f.now}, g.ID); !errors.Is(err, ErrGrantNotFound) {
		t.Fatal("outsider read", err)
	}
	inbox, _, err := f.svc.List(ctx, grantIdentity{f.approver, &f.now}, "pending", 20)
	if err != nil || len(inbox) != 1 || !inbox[0].Approver || inbox[0].Review.Namespace != "payments" {
		t.Fatal("approver inbox", inbox, err)
	}
	if own, _, err := f.svc.List(ctx, grantIdentity{f.requester, &f.now}, "pending", 20); err != nil || len(own) != 0 {
		t.Fatal("own request in own inbox", own, err)
	}
	if mine, _, err := f.svc.List(ctx, grantIdentity{f.requester, &f.now}, "requested", 20); err != nil || len(mine) != 1 || mine[0].Approver {
		t.Fatal("requested view", mine, err)
	}
	// An outsider cannot revoke; the requester withdraws.
	if _, _, err := f.svc.Revoke(ctx, grantIdentity{f.outside, &f.now}, g.ID, 1, "r"); !errors.Is(err, value.ErrNotApprover) {
		t.Fatal("outsider revoked", err)
	}
	revoked, _, err := f.svc.Revoke(ctx, grantIdentity{f.requester, &f.now}, g.ID, 1, "withdraw")
	if err != nil || revoked.Phase(f.now) != value.GrantRevoked || revoked.Revision != 2 {
		t.Fatal("withdraw", err)
	}
	if _, _, err := f.svc.Decide(ctx, grantIdentity{f.approver, &f.now}, g.ID, true, "late", "late"); !errors.Is(err, value.ErrGrantNotPending) {
		t.Fatal("decided a withdrawn request", err)
	}
	// A denial records the reviewer without step-up and never covers.
	d := f.request(t, 3, nil)
	plain := f.approver
	plain.Assurance = identity.Assurance{}
	denied, _, err := f.svc.Decide(ctx, grantIdentity{plain, &f.now}, d.ID, false, "not justified", "deny")
	if err != nil || denied.Phase(f.now) != value.GrantDenied {
		t.Fatal("deny", err)
	}
	if _, _, err := f.svc.Covering(ctx, grantIdentity{f.requester, &f.now}, d.CaptureID, d.ExecutionDigest, f.target); !errors.Is(err, value.ErrGrantDenied) {
		t.Fatal("denied grant covers", err)
	}
	// An approved grant revoked by the approver stops covering.
	a := f.approve(t, f.request(t, 4, nil))
	if _, _, err := f.svc.Revoke(ctx, grantIdentity{f.approver, &f.now}, a.ID, 2, "stop"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Covering(ctx, grantIdentity{f.requester, &f.now}, a.CaptureID, a.ExecutionDigest, f.target); !errors.Is(err, value.ErrGrantRevoked) {
		t.Fatal("revoked grant covers", err)
	}
	// One request per capture identity; the same key replays it.
	if _, _, err := f.svc.Request(ctx, grantIdentity{f.requester, &f.now}, func() GrantRequestInput { in := f.input(4, nil); in.IdempotencyKey = "another"; return in }()); !errors.Is(err, ErrGrantConflict) {
		t.Fatal("second request for one capture", err)
	}
	if again, replay, err := f.svc.Request(ctx, grantIdentity{f.requester, &f.now}, f.input(3, nil)); err != nil || !replay || again.ID != d.ID {
		t.Fatal("request replay", err)
	}
	// A request needs current collection eligibility and the actor's own preview.
	if _, _, err := f.svc.Request(ctx, grantIdentity{f.approver, &f.now}, f.input(5, nil)); err == nil {
		t.Fatal("a non-actor opened a request")
	}
	// The review window lapses.
	p := f.request(t, 6, nil)
	f.now = p.ReviewUntil
	if _, _, err := f.svc.Decide(ctx, grantIdentity{f.approver, &f.now}, p.ID, true, "late", "late-2"); !errors.Is(err, value.ErrGrantNotPending) {
		t.Fatal("decided after the review window", err)
	}
}

// REQ-INV-002: exact children after verified commit share one finite pool;
// never another client, capture or unpublished artifact.
func TestGrantResultAccessPool(t *testing.T) {
	ctx := context.Background()
	f := newGrantFixture(t)
	g := f.approve(t, f.request(t, 7, f.access()))
	if !g.ExpiresAt.Equal(f.now.Add(time.Hour)) || g.ResultAccessDigest != ResultAccessDigest(g.CaptureID, g.ExecutionDigest, NormalizeResultAccess(*f.access())) {
		t.Fatal("result access binding", g.ExpiresAt)
	}
	out := value.VerifiedOutput{CaptureID: g.CaptureID, ActionID: "a1", ArtifactID: grantID(500), ExecutionDigest: g.ExecutionDigest, ArtifactDigest: artifact.Digest{5}, Target: f.target}
	if _, _, err := f.svc.Materialize(ctx, g.ID, "console", out); !errors.Is(err, value.ErrGrantScope) {
		t.Fatal("unpublished artifact became a child", err)
	}
	f.store.locator[out.ArtifactID] = g.CaptureID
	c1, replay, err := f.svc.Materialize(ctx, g.ID, "console", out)
	if err != nil || replay {
		t.Fatal(err)
	}
	if again, replay, err := f.svc.Materialize(ctx, g.ID, "console", out); err != nil || !replay || again.ID != c1.ID {
		t.Fatal("duplicate commit delivery", err)
	}
	c2, _, err := f.svc.Materialize(ctx, g.ID, "agent", out)
	if err != nil || f.store.rows[g.ID].Spent.Artifacts != 1 {
		t.Fatal("a second client charged another artifact", err)
	}
	second := out
	second.ArtifactID = grantID(501)
	f.store.locator[second.ArtifactID] = g.CaptureID
	if _, _, err := f.svc.Materialize(ctx, g.ID, "console", second); !errors.Is(err, value.ErrGrantPoolExhausted) {
		t.Fatal("max artifacts exceeded", err)
	}
	for name, bad := range map[string]struct {
		client string
		mut    func(*value.VerifiedOutput)
	}{
		"unlisted client":  {"cli", func(*value.VerifiedOutput) {}},
		"other action":     {"console", func(o *value.VerifiedOutput) { o.ActionID = "a2" }},
		"other capture":    {"console", func(o *value.VerifiedOutput) { o.CaptureID = grantID(8) }},
		"forged execution": {"console", func(o *value.VerifiedOutput) { o.ExecutionDigest = artifact.Digest{7} }},
	} {
		o := out
		bad.mut(&o)
		if _, _, err := f.svc.Materialize(ctx, g.ID, bad.client, o); !errors.Is(err, value.ErrGrantScope) {
			t.Fatal(name, err)
		}
	}
	agent := f.requester
	agent.Principal.ClientID = "agent"
	use := func(who identity.Identity, child value.GrantChild, id int, bytes int64) error {
		_, _, err := f.svc.Use(ctx, grantIdentity{who, &f.now}, child.ID, grantID(id), value.GrantUse{Operation: value.GrantDownloadOperation, Bytes: bytes, Operations: 1})
		return err
	}
	if err := use(f.requester, c1, 600, 60); err != nil {
		t.Fatal(err)
	}
	// Both clients spend one pool: 60 + 40 = the 100-byte cap.
	if err := use(agent, c2, 601, 40); err != nil {
		t.Fatal(err)
	}
	if err := use(f.requester, c1, 602, 1); !errors.Is(err, value.ErrGrantPoolExhausted) {
		t.Fatal("pool exceeded", err)
	}
	// A retry of an earlier reservation is idempotent; the same use ID with
	// another amount is a conflict.
	if err := use(f.requester, c1, 600, 60); err != nil {
		t.Fatal("reservation replay", err)
	}
	if err := use(f.requester, c1, 600, 61); !errors.Is(err, ErrGrantConflict) {
		t.Fatal("changed replay", err)
	}
	// The child's client is binding; another human never uses it.
	if err := use(agent, c1, 603, 0); err == nil {
		t.Fatal("another client used a child")
	}
	if err := use(f.outside, c1, 604, 0); err == nil {
		t.Fatal("another person used a child")
	}
	// Revocation of the parent stops every child use and new children.
	if _, _, err := f.svc.Revoke(ctx, grantIdentity{f.approver, &f.now}, g.ID, 2, "stop"); err != nil {
		t.Fatal(err)
	}
	if err := use(f.requester, c1, 605, 0); !errors.Is(err, value.ErrGrantRevoked) {
		t.Fatal("revoked parent used", err)
	}
	if _, _, err := f.svc.Materialize(ctx, g.ID, "console", out); !errors.Is(err, value.ErrGrantRevoked) {
		t.Fatal("revoked parent materialized", err)
	}
	// NotAfter caps the approved lifetime.
	short := f.access()
	short.NotAfter = f.now.Add(10 * time.Minute)
	s := f.approve(t, f.request(t, 9, short))
	if !s.ExpiresAt.Equal(short.NotAfter) {
		t.Fatal("not_after does not cap expiry", s.ExpiresAt)
	}
	if !slices.Equal(s.ResultAccess.ClientIDs, []string{"agent", "console"}) {
		t.Fatal("client set not normalized", s.ResultAccess.ClientIDs)
	}
}
