package capture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	access "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

func fixtureID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

// These test-only ports model effects and blocking changes. They are not SQL,
// Kubernetes, recovery or permission source qualification. Eligibility uses the
// actual shared evaluator and identity uses an actual request-owned handle.
type investigationFixture struct {
	now                                                   time.Time
	svc                                                   ContextInvestigation
	target                                                targets.PodResolution
	actor                                                 identity.Principal
	audience                                              artifact.AudienceAssignment
	cap                                                   planning.ContextCapability
	store                                                 ContextStorageObservation
	epoch                                                 string
	denied, missing, recoveryBlocked, noProof             bool
	unknownCommit, unknownPreview                         bool
	afterStore, afterStorage, afterAdmission, afterReplay func()
	identityChange                                        string
	newIDs, targetReads, previewReads, admissions         atomic.Int64
	mu                                                    sync.Mutex
	previews                                              map[string]value.ContextPreview
	accepted                                              map[string]value.Accepted
	policyGeneration                                      int64
}

func newInvestigationFixture() *investigationFixture {
	f := &investigationFixture{now: time.Now().UTC().Truncate(time.Microsecond), epoch: fixtureID(3), previews: map[string]value.ContextPreview{}, accepted: map[string]value.Accepted{}, policyGeneration: 1}
	f.actor = identity.Principal{Issuer: "https://identity.example.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}
	f.target = targets.PodResolution{Request: targets.Request{ClusterID: fixtureID(4), Namespace: configuration.NamespaceRef{Name: "payments", UID: "ns"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "deployment"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "ns", Name: "api-a", UID: "pod", NodeName: "worker", ControllerUID: "rs"}, NodeUID: "node", NodeBootID: fixtureID(5), PodResourceVersion: "1", WorkloadResourceVersion: "2"}
	f.audience = artifact.AudienceAssignment{Kind: "User", Issuer: f.actor.Issuer, SubjectID: f.actor.Subject, Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: fixtureID(6), BasisDigest: artifact.Digest{1}}
	f.cap = planning.ContextCapability{Enabled: true, Revision: identity.Revision{UID: "capability", Generation: 1, Digest: [32]byte{2}}, CollectorVersion: "test-1", CollectorImageDigest: artifact.Digest{3}, ProjectionDigest: compiler.ProjectionDigest()}
	f.store = ContextStorageObservation{Selection: value.ContextStorageSelection{StoreID: fixtureID(7), AllocationID: fixtureID(8), PoolRevision: 1, AllocationRevision: 1, BindingRevision: identity.Revision{UID: "binding", Generation: 1, Digest: [32]byte{4}}}, Binding: value.StorageBinding{RootID: fixtureID(1), ClusterID: fixtureID(4), NamespaceUID: "ns", WorkloadUID: "deployment", AllocationID: fixtureID(8), Revision: identity.Revision{UID: "binding", Generation: 1, Digest: [32]byte{4}}}}
	f.svc = ContextInvestigation{RootID: fixtureID(1), InstallationID: fixtureID(2), Previews: f, Replay: f, Admission: f, Resolution: f, Targets: f, Eligibility: access.Evaluator{Permissions: f, Now: func() time.Time { return f.now }}, Capabilities: f, Retention: f, Storage: f, Processing: f, Recovery: f, Lifetime: 5 * time.Minute, Now: func() time.Time { return f.now }, NewID: func() string { return fixtureID(100 + int(f.newIDs.Add(1))) }}
	return f
}

func (f *investigationFixture) intent() value.ContextIntent {
	return value.ContextIntent{Target: targets.WorkloadRequest{ClusterID: fixtureID(4), Namespace: "payments", Kind: "Deployment", Name: "api"}, Diagnostic: value.ContextDiagnosticName, RequestedSeconds: 60}
}

type fixtureIdentityResolver struct{ f *investigationFixture }

func (r fixtureIdentityResolver) Resolve(ctx context.Context, _ string) (identity.Identity, error) {
	if ctx.Err() != nil || r.f.denied {
		return identity.Identity{}, identity.ErrDenied
	}
	i := identity.Identity{Principal: r.f.actor, Policy: identity.Revision{UID: "identity-policy", Generation: 1, Digest: [32]byte{9}}, Scopes: []string{"evidence:capture", "evidence:read"}, Groups: []string{"dev-team"}, VerifiedAt: r.f.now, ValidUntil: r.f.now.Add(5 * time.Second)}
	switch r.f.identityChange {
	case "groups":
		i.Groups = nil
	case "scopes":
		i.Scopes = []string{"evidence:read"}
	case "policy":
		i.Policy.Generation++
	}
	return i, nil
}
func (f *investigationFixture) source(t *testing.T, ctx context.Context) identities.CurrentIdentity {
	t.Helper()
	s, _, err := identities.NewBearerRequest(ctx, fixtureIdentityResolver{f}, "test-credential", func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func (f *investigationFixture) Permissions(_ context.Context, t authorization.Target) (authorization.Projection, error) {
	p := authorization.Projection{Target: t, Revision: identity.Revision{UID: "permissions", Generation: 1, Digest: [32]byte{5}}, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second), DeniesComplete: true, DeniesObservedAt: f.now, DeniesFreshUntil: f.now.Add(5 * time.Second)}
	a := authorization.CurrentAssignment{Audience: f.audience, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}
	p.Allows = []authorization.CurrentAssignment{a}
	if f.denied {
		p.Denies = []authorization.CurrentAssignment{a}
	}
	return p, nil
}
func (f *investigationFixture) ResolveWorkload(ctx context.Context, _ targets.WorkloadRequest) (targets.PodResolution, error) {
	return f.ResolvePod(ctx, f.target.Request)
}
func (f *investigationFixture) ResolvePod(_ context.Context, _ targets.Request) (targets.PodResolution, error) {
	f.targetReads.Add(1)
	if f.missing {
		return targets.PodResolution{}, targets.ErrUnavailable
	}
	p := f.target
	p.ObservedAt = f.now
	p.FreshUntil = f.now.Add(5 * time.Second)
	return p, nil
}
func (f *investigationFixture) ContextCapability(context.Context, authorization.Target) (planning.ContextCapability, error) {
	c := f.cap
	c.ObservedAt = f.now
	c.FreshUntil = f.now.Add(5 * time.Second)
	return c, nil
}
func (f *investigationFixture) ContextStorage(context.Context, authorization.Target) (ContextStorageObservation, error) {
	s := f.store
	s.Binding.ObservedAt = f.now
	s.Binding.FreshUntil = f.now.Add(5 * time.Second)
	if !f.store.Binding.FreshUntil.IsZero() {
		s.Binding.FreshUntil = f.store.Binding.FreshUntil
	}
	if f.afterStorage != nil {
		f.afterStorage()
	}
	return s, nil
}
func (f *investigationFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	if f.recoveryBlocked {
		return artifact.RecoveryProof{}, value.ErrUnavailable
	}
	return artifact.RecoveryProof{InstallationID: fixtureID(2), IssuerEpoch: f.epoch, Revision: identity.Revision{UID: "recovery", Generation: 1, Digest: [32]byte{6}}, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}, nil
}
func (f *investigationFixture) Resolve(_ context.Context, in privacy.Input) (privacy.Resolution, error) {
	r := identity.Revision{UID: fixtureID(9), Generation: 1, Digest: [32]byte{7}}
	set := privacy.PolicySet{Target: in.Target, Revision: r, Complete: true, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second), Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: f.policyGeneration, Digest: [32]byte{8}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 60, MaximumSeconds: 3600, DeletionBudgetSeconds: 10}}}
	if !f.noProof {
		set.Proof = artifact.RetentionProof{RootID: fixtureID(1), ClusterID: in.Target.ClusterID, NamespaceUID: in.Target.NamespaceUID, WorkloadUID: in.Target.WorkloadUID, PodUID: in.Target.PodUID, Topology: r, Policy: r, Selectors: r, ObservedAt: f.now, ValidUntil: set.FreshUntil, SourceCount: 1, Sources: [2]artifact.RetentionSourceVersion{{ClusterID: in.Target.ClusterID, ControlNamespaceUID: "control", Epoch: fixtureID(3), Hub: true, ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: r}}}
	}
	return privacy.Resolve(set, in, f.now)
}
func (f *investigationFixture) CreateContextPreview(_ context.Context, p value.ContextPreview) error {
	f.mu.Lock()
	f.previews[p.ID] = p.Clone()
	f.mu.Unlock()
	if f.afterStore != nil {
		f.afterStore()
	}
	if f.unknownPreview {
		return value.ErrUnavailable
	}
	return nil
}
func (f *investigationFixture) ReadContextPreview(_ context.Context, root, id string, actor identity.Principal) (value.ContextPreview, error) {
	f.previewReads.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.previews[id]
	if !ok || p.RootID != root || p.Actor != actor {
		return value.ContextPreview{}, value.ErrDenied
	}
	if !p.Current(f.now) {
		return value.ContextPreview{}, value.ErrPreviewExpired
	}
	return p.Clone(), nil
}
func fixtureKey(i identity.Principal, key string) string {
	return i.Issuer + "/" + i.Subject + "/" + i.ClientID + "/" + key
}
func (f *investigationFixture) LookupContextAdmission(_ context.Context, q value.ReplayQuery) (value.Accepted, bool, error) {
	if !ValidReplayQuery(q, f.now) || f.denied {
		return value.Accepted{}, false, value.ErrDenied
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.accepted[fixtureKey(q.Identity.Principal, q.IdempotencyKey)]
	if ok && a.SubmissionDigest != q.SubmissionDigest {
		return value.Accepted{}, false, value.ErrConflict
	}
	if f.afterReplay != nil {
		f.afterReplay()
	}
	a.MetadataValidUntil = identity.Earlier(q.Identity.ValidUntil, q.Recovery.FreshUntil)
	return a, ok, nil
}
func (f *investigationFixture) AdmitReviewedContext(_ context.Context, previewID string, a value.Admission) (value.Accepted, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fixtureKey(a.Plan.Input.Executor, a.IdempotencyKey)
	if old, ok := f.accepted[key]; ok {
		old.Replay = true
		old.MetadataValidUntil = identity.Earlier(a.Eligibility.ValidUntil, a.Recovery.FreshUntil)
		return old, nil
	}
	p, ok := f.previews[previewID]
	if !ok || p.Actor != a.Plan.Input.Executor || !p.Current(f.now) {
		return value.Accepted{}, value.ErrChanged
	}

	for _, old := range f.accepted {
		if old.CaptureID == a.Plan.Input.CaptureID {
			return value.Accepted{}, value.ErrConflict
		}
	}
	f.admissions.Add(1)
	in := a.Plan.Input
	t, r := in.Target, in.Retention
	e := artifact.ContextExpectation{ExecutionClass: t.ExecutionClass, Registration: a.Registration, CaseID: a.CaseID, OccurrenceID: a.OccurrenceID, NodeUID: t.NodeUID, NodeBootID: t.NodeBootID, PodUID: t.Request.PodUID, Namespace: t.Request.Namespace.Name, NamespaceUID: t.Request.Namespace.UID, WorkloadUID: t.Request.Workload.UID, CollectorVersion: in.Capability.CollectorVersion, CollectorImageDigest: in.Capability.CollectorImageDigest, RecipeDigest: a.Plan.RecipeDigest, PlanDigest: a.Plan.ScopeDigest, CaptureUID: in.CaptureID, ActionID: "pod-status", DataClass: "metadata", PurposeRef: r.PurposeRef, Audience: slices.Clone(a.Eligibility.DefaultAudience), RequestedAgeSeconds: r.RequestedSeconds, MaximumAgeSeconds: r.MaximumSeconds, DeletionBudgetSeconds: r.DeletionBudgetSeconds, RetentionRules: slices.Clone(r.Policies), TriggeredAt: a.Registration.AnchorAt}
	out := value.Accepted{MetadataValidUntil: identity.Earlier(a.Eligibility.ValidUntil, a.Recovery.FreshUntil), CaptureID: in.CaptureID, State: value.PendingAudit, ScopeDigest: a.Plan.ScopeDigest, SubmissionDigest: a.SubmissionDigest, Expectation: e, Pin: t.Pin, CreatedAt: f.now, Deadline: in.Deadline}
	f.accepted[key] = out
	if f.afterAdmission != nil {
		f.afterAdmission()
	}
	if f.unknownCommit {
		return value.Accepted{}, value.ErrUnavailable
	}
	return out, nil
}
func (f *investigationFixture) preview(t *testing.T) value.ContextPreview {
	t.Helper()
	p, err := f.svc.Preview(context.Background(), f.source(t, context.Background()), f.intent())
	if err != nil {
		t.Fatal(err)
	}
	return p.Preview
}
func (f *investigationFixture) request(t *testing.T, p value.ContextPreview, key string) (value.Accepted, error) {
	t.Helper()
	return f.svc.Request(context.Background(), f.source(t, context.Background()), p.ID, key)
}

func TestContextPreviewPassiveAndAssessment(t *testing.T) {
	f := newInvestigationFixture()
	r, err := f.svc.Preview(context.Background(), f.source(t, context.Background()), f.intent())
	if err != nil {
		t.Fatal(err)
	}
	if f.admissions.Load() != 0 || f.previewReads.Load() != 0 || len(f.accepted) != 0 || !ValidContextPreview(r.Preview) {
		t.Fatal("preview executed work or invalid blueprint")
	}
	if r.Assessment.PlanDigest != r.Preview.ScopeDigest || r.Assessment.RulesDigest != r.Preview.AssessmentRulesDigest || r.Assessment.ID != r.Preview.AssessmentID || r.Assessment.Retention.AccessAgeSeconds != 60 {
		t.Fatal("assessment differs from reviewed plan")
	}
	b, _ := json.Marshal(r.Preview)
	var object map[string]json.RawMessage
	if json.Unmarshal(b, &object) != nil {
		t.Fatal("invalid preview")
	}
	for _, key := range []string{"Identity", "VerifiedIdentity", "Recovery", "Proof", "Assessment", "AnchorAt", "ExpiresAt"} {
		if _, ok := object[key]; ok {
			t.Fatalf("persisted runtime authority %s", key)
		}
	}
	r.Preview.CanonicalScope[0] = '!'
	r.Preview.Audience[0].SubjectID = "replacement"
	if !ValidContextPreview(f.previews[r.Preview.ID]) {
		t.Fatal("returned preview aliases stored blueprint")
	}
}

func TestContextRetentionStartsAtRequestAfterReview(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	f.now = f.now.Add(2 * time.Minute)
	a, err := f.request(t, p, "request-1")
	if err != nil {
		t.Fatal(err)
	}
	r := a.Expectation.Registration
	if !r.AnchorAt.Equal(f.now) || !r.ExpiresAt.Equal(f.now.Add(time.Minute)) || a.CaptureID != p.CaptureID || a.Expectation.CaseID != p.CaseID || a.ScopeDigest != p.ScopeDigest {
		t.Fatal("review consumed retention or changed accepted identity")
	}
}

func TestContextUnknownCommitRecoversAfterExpiryAndPodDisappearance(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	f.unknownCommit = true
	if _, err := f.request(t, p, "original"); !errors.Is(err, value.ErrUnavailable) {
		t.Fatal(err)
	}
	beforeReads, beforeIDs := f.targetReads.Load(), f.newIDs.Load()
	f.now = f.now.Add(10 * time.Minute)
	f.missing = true
	f.noProof = true
	f.cap.Enabled = false
	f.store = ContextStorageObservation{}
	delete(f.previews, p.ID)
	a, err := f.request(t, p, "original")
	if err != nil || !a.Replay || a.CaptureID != p.CaptureID || f.admissions.Load() != 1 || f.targetReads.Load() != beforeReads || f.newIDs.Load() != beforeIDs {
		t.Fatal("failed exact recovery without original acquisition facts", err)
	}
	if f.previewReads.Load() != 1 {
		t.Fatal("replay consulted expired preview")
	}
	f.denied = true
	if _, err = f.svc.Request(context.Background(), fixtureIdentityResolverHandle{f}, p.ID, "original"); err == nil {
		t.Fatal("revoked caller read accepted operation")
	}
}

// Explicit fake used only to assert the coordinator does not accept a revoked
// principal. Production transport constructs its own sealed request handle.
type fixtureIdentityResolverHandle struct{ f *investigationFixture }

func (h fixtureIdentityResolverHandle) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	return fixtureIdentityResolver{h.f}.Resolve(ctx, "")
}

func TestContextMaterialChangesRequireReview(t *testing.T) {
	for name, change := range map[string]func(*investigationFixture, value.ContextPreview){
		"pod replacement": func(f *investigationFixture, _ value.ContextPreview) {
			f.target.Request.PodUID = "replacement"
			f.target.Pin.UID = "replacement"
		},
		"node reboot":          func(f *investigationFixture, _ value.ContextPreview) { f.target.NodeBootID = fixtureID(33) },
		"collector":            func(f *investigationFixture, _ value.ContextPreview) { f.cap.CollectorImageDigest[0]++ },
		"ceiling":              func(f *investigationFixture, _ value.ContextPreview) { f.cap.Revision.Digest[0]++ },
		"retention":            func(f *investigationFixture, _ value.ContextPreview) { f.policyGeneration++ },
		"audience":             func(f *investigationFixture, _ value.ContextPreview) { f.audience.AssignmentID = fixtureID(34) },
		"allocation":           func(f *investigationFixture, _ value.ContextPreview) { f.store.Selection.PoolRevision++ },
		"recovery incarnation": func(f *investigationFixture, _ value.ContextPreview) { f.epoch = fixtureID(35) },
		"assessment rules": func(f *investigationFixture, p value.ContextPreview) {
			p.AssessmentRulesDigest[0]++
			f.previews[p.ID] = p
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newInvestigationFixture()
			p := f.preview(t)
			change(f, p)
			if _, err := f.request(t, p, "one"); !errors.Is(err, value.ErrChanged) {
				t.Fatal("expected fresh review", err)
			}
			if f.admissions.Load() != 0 {
				t.Fatal("changed scope admitted")
			}
		})
	}
}

func TestContextNoBroadPresetSubstitution(t *testing.T) {
	f := newInvestigationFixture()
	in := f.intent()
	in.Diagnostic = "incident-context/v1"
	if _, err := f.svc.Preview(context.Background(), f.source(t, context.Background()), in); !errors.Is(err, value.ErrDiagnosticUnavailable) {
		t.Fatal(err)
	}
	if f.targetReads.Load() != 0 || f.newIDs.Load() != 0 {
		t.Fatal("unsupported diagnostic started preparation")
	}
}

func TestContextBlockingWorkKeepsOriginalDeadlines(t *testing.T) {
	for _, stage := range []string{"draft write", "storage read", "admission reply"} {
		t.Run(stage, func(t *testing.T) {
			f := newInvestigationFixture()
			expire := func() { f.now = f.now.Add(5 * time.Second) }
			if stage == "draft write" {
				f.afterStore = expire
				if _, err := f.svc.Preview(context.Background(), f.source(t, context.Background()), f.intent()); err == nil {
					t.Fatal("expired preview response")
				}
				return
			}
			p := f.preview(t)
			if stage == "storage read" {
				f.afterStorage = expire
			} else {
				f.afterAdmission = expire
			}
			if _, err := f.request(t, p, "one"); err == nil {
				t.Fatal("renewed original request observations")
			}
			if stage == "storage read" && f.admissions.Load() != 0 {
				t.Fatal("expired facts admitted")
			}
			if stage == "admission reply" {
				f.afterAdmission = nil
				a, err := f.request(t, p, "one")
				if err != nil || !a.Replay || f.admissions.Load() != 1 {
					t.Fatal("lost committed response not recoverable", err)
				}
			}
		})
	}
}

func TestContextPreviewExpiryOwnershipAndAdmissionKey(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		f := newInvestigationFixture()
		p := f.preview(t)
		f.now = p.Deadline
		if _, err := f.request(t, p, "one"); !errors.Is(err, value.ErrPreviewExpired) {
			t.Fatal(err)
		}
		if f.admissions.Load() != 0 {
			t.Fatal("expired draft admitted")
		}
	})
	t.Run("client", func(t *testing.T) {
		f := newInvestigationFixture()
		p := f.preview(t)
		f.actor.ClientID = "other-client"
		if _, err := f.request(t, p, "one"); !errors.Is(err, value.ErrDenied) {
			t.Fatal(err)
		}
	})
	t.Run("changed preview same key", func(t *testing.T) {
		f := newInvestigationFixture()
		p := f.preview(t)
		if _, err := f.request(t, p, "one"); err != nil {
			t.Fatal(err)
		}
		other := f.preview(t)
		reads := f.previewReads.Load()
		if _, err := f.request(t, other, "one"); !errors.Is(err, value.ErrConflict) || f.previewReads.Load() != reads || f.admissions.Load() != 1 {
			t.Fatal("conflict consumed new draft", err)
		}
	})
	t.Run("same preview another key", func(t *testing.T) {
		f := newInvestigationFixture()
		p := f.preview(t)
		if _, err := f.request(t, p, "one"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.request(t, p, "two"); !errors.Is(err, value.ErrConflict) || f.admissions.Load() != 1 {
			t.Fatal("same draft generated second capture", err)
		}
	})
}

func TestContextRequiresProtectedAuthorityAndNoDetachedContext(t *testing.T) {
	t.Run("retention proof", func(t *testing.T) {
		f := newInvestigationFixture()
		f.noProof = true
		if _, err := f.svc.Preview(context.Background(), f.source(t, context.Background()), f.intent()); err == nil {
			t.Fatal("arithmetic authorized acquisition")
		}
	})
	t.Run("recovery", func(t *testing.T) {
		f := newInvestigationFixture()
		f.recoveryBlocked = true
		if _, err := f.svc.Preview(context.Background(), f.source(t, context.Background()), f.intent()); err == nil || f.targetReads.Load() != 0 {
			t.Fatal("blocked recovery allowed preview")
		}
	})
	t.Run("canceled owner", func(t *testing.T) {
		f := newInvestigationFixture()
		p := f.preview(t)
		ctx, cancel := context.WithCancel(context.Background())
		source := f.source(t, ctx)
		cancel()
		if _, err := f.svc.Request(context.Background(), source, p.ID, "one"); err == nil || f.admissions.Load() != 0 {
			t.Fatal("background detached original request")
		}
	})
	t.Run("revoked during draft write", func(t *testing.T) {
		f := newInvestigationFixture()
		f.afterStore = func() { f.denied = true }
		if _, err := f.svc.Preview(context.Background(), f.source(t, context.Background()), f.intent()); err == nil || f.admissions.Load() != 0 {
			t.Fatal("revoked preview disclosed")
		}
	})
	t.Run("unknown draft write", func(t *testing.T) {
		f := newInvestigationFixture()
		f.unknownPreview = true
		if _, err := f.svc.Preview(context.Background(), f.source(t, context.Background()), f.intent()); err == nil || len(f.previews) != 1 || f.admissions.Load() != 0 {
			t.Fatal("unknown passive write executed")
		}
	})
}

func TestContextProtectedReasonReferenceRequiresProducedEnvelope(t *testing.T) {
	f := newInvestigationFixture()
	in := f.intent()
	in.Reason = &value.ProtectedReasonRef{ID: fixtureID(40), CiphertextDigest: artifact.Digest{4}}
	if _, err := f.svc.Preview(context.Background(), f.source(t, context.Background()), in); err == nil || len(f.previews) != 0 {
		t.Fatal("unproduced reference accepted or persisted")
	}
}

func TestContextConcurrentSubmissionKeepsOneOperation(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			source, _, err := identities.NewBearerRequest(context.Background(), fixtureIdentityResolver{f}, "test", func() time.Time { return f.now })
			if err == nil {
				var a value.Accepted
				a, err = f.svc.Request(context.Background(), source, p.ID, "one")
				if err == nil && a.CaptureID != p.CaptureID {
					err = errors.New("changed operation")
				}
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.admissions.Load() != 1 {
		t.Fatal("parallel request spent twice")
	}
}

func TestContextPreviewIntegrityAndSerializedBounds(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	for name, mutate := range map[string]func(*value.ContextPreview){
		"altered scope":           func(p *value.ContextPreview) { p.CanonicalScope[0] = '!' },
		"valid JSON wrong digest": func(p *value.ContextPreview) { p.CanonicalScope = []byte(`{}`) },
		"invalid JSON matching digest": func(p *value.ContextPreview) {
			p.CanonicalScope = []byte(`not json`)
			p.ScopeDigest = artifact.Digest(sha256.Sum256(p.CanonicalScope))
		},
		"expanded minimized blueprint": func(p *value.ContextPreview) {
			p.CanonicalScope = []byte(`"` + strings.Repeat("a", value.MaxContextPreviewScope-2) + `"`)
			p.ScopeDigest = artifact.Digest(sha256.Sum256(p.CanonicalScope))
			p.Audience = make([]artifact.AudienceAssignment, 32)
			for n := range p.Audience {
				a := f.audience
				a.AssignmentID = fixtureID(500 + n)
				a.Issuer = strings.Repeat("x", 2048)
				p.Audience[n] = a
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := p.Clone()
			mutate(&bad)
			if ValidContextPreview(bad) {
				t.Fatal("invalid persisted integrity accepted")
			}
		})
	}
	if ContextRequestDigest(p.ID) == ContextRequestDigest(fixtureID(999)) || ContextRequestDigest("invalid") != (artifact.Digest{}) {
		t.Fatal("request identity digest collision or invalid input")
	}
}

func TestContextCurrentIdentityChangesAfterSQLDenyResponse(t *testing.T) {
	for _, stage := range []string{"admission", "replay"} {
		for _, claim := range []string{"groups", "scopes", "policy"} {
			t.Run(stage+"/"+claim, func(t *testing.T) {
				f := newInvestigationFixture()
				p := f.preview(t)
				if stage == "replay" {
					if _, err := f.request(t, p, "one"); err != nil {
						t.Fatal(err)
					}
					f.afterReplay = func() { f.identityChange = claim }
				} else {
					f.afterAdmission = func() { f.identityChange = claim }
				}
				if _, err := f.request(t, p, "one"); err == nil {
					t.Fatal("same principal with changed current authority received result")
				}
				if f.admissions.Load() != 1 {
					t.Fatal("response fencing generated another effect")
				}
			})
		}
	}
}

func TestContextPreviewRetainsShorterStorageObservation(t *testing.T) {
	f := newInvestigationFixture()
	f.store.Binding.FreshUntil = f.now.Add(time.Second)
	ctx := context.Background()
	result, err := f.svc.Preview(ctx, f.source(t, ctx), f.intent())
	if err != nil {
		t.Fatal(err)
	}
	if !result.ValidUntil.Equal(f.store.Binding.FreshUntil) {
		t.Fatalf("preview extended storage observation: %s != %s", result.ValidUntil, f.store.Binding.FreshUntil)
	}
}

func (f *investigationFixture) ResolveOrCloseContextRequest(_ context.Context, q value.ReplayQuery) (value.ContextRequestDisposition, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !ValidReplayQuery(q, f.now) || f.denied {
		return value.ContextRequestDisposition{}, value.ErrDenied
	}
	if a, ok := f.accepted[fixtureKey(q.Identity.Principal, q.IdempotencyKey)]; ok {
		if a.SubmissionDigest != q.SubmissionDigest {
			return value.ContextRequestDisposition{}, value.ErrConflict
		}
		a.MetadataValidUntil = identity.Earlier(q.Identity.ValidUntil, q.Recovery.FreshUntil)
		return value.ContextRequestDisposition{State: value.RequestAccepted, Accepted: &a, ValidUntil: a.MetadataValidUntil}, nil
	}
	// Test-only negative marker; the SQL adapter qualifies durable close semantics.
	delete(f.previews, q.PreviewID)
	return value.ContextRequestDisposition{State: value.RequestClosed, ValidUntil: identity.Earlier(q.Identity.ValidUntil, q.Recovery.FreshUntil)}, nil
}
