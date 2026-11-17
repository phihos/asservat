package capture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
// Kubernetes or permission source qualification. Eligibility uses the
// actual shared evaluator and identity uses an actual request-owned handle.
type investigationFixture struct {
	now                                       time.Time
	svc                                       ContextInvestigation
	target                                    targets.PodResolution
	actor                                     identity.Principal
	audience                                  artifact.AudienceAssignment
	cap                                       planning.ContextCapability
	store                                     ContextStorageObservation
	epoch                                     string
	denied, missing                           bool
	unknownCommit                             bool
	afterStorage, afterAdmission, afterReplay func()
	identityChange                            string
	newIDs, targetReads, admissions           atomic.Int64
	mu                                        sync.Mutex
	accepted                                  map[string]value.Accepted
	policyGeneration                          int64
}

func newInvestigationFixture() *investigationFixture {
	f := &investigationFixture{now: time.Now().UTC().Truncate(time.Microsecond), epoch: fixtureID(3), accepted: map[string]value.Accepted{}, policyGeneration: 1}
	f.actor = identity.Principal{Issuer: "https://identity.example.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}
	f.target = targets.PodResolution{Request: targets.Request{ClusterID: fixtureID(4), Namespace: configuration.NamespaceRef{Name: "payments", UID: "ns"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "deployment"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "ns", Name: "api-a", UID: "pod", NodeName: "worker", ControllerUID: "rs"}, NodeUID: "node", NodeBootID: fixtureID(5), PodResourceVersion: "1", WorkloadResourceVersion: "2"}
	f.audience = artifact.AudienceAssignment{Kind: "User", Issuer: f.actor.Issuer, SubjectID: f.actor.Subject, Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: fixtureID(6), BasisDigest: artifact.Digest{1}}
	f.cap = planning.ContextCapability{Enabled: true, Revision: identity.Revision{UID: "capability", Generation: 1, Digest: [32]byte{2}}, CollectorVersion: "test-1", CollectorImageDigest: artifact.Digest{3}, ProjectionDigest: compiler.ProjectionDigest()}
	f.store = ContextStorageObservation{Selection: value.ContextStorageSelection{StoreID: fixtureID(7), AllocationID: fixtureID(8), PoolRevision: 1, AllocationRevision: 1, BindingRevision: identity.Revision{UID: "binding", Generation: 1, Digest: [32]byte{4}}}, Binding: value.StorageBinding{RootID: fixtureID(1), ClusterID: fixtureID(4), NamespaceUID: "ns", WorkloadUID: "deployment", AllocationID: fixtureID(8), Revision: identity.Revision{UID: "binding", Generation: 1, Digest: [32]byte{4}}}}
	f.svc = ContextInvestigation{RootID: fixtureID(1), InstallationID: fixtureID(2), Replay: f, Admission: f, Targets: f, Eligibility: access.Evaluator{Permissions: f, Now: func() time.Time { return f.now }}, Capabilities: f, Retention: f, Storage: f, Processing: f, Lifetime: 5 * time.Minute, Now: func() time.Time { return f.now }, NewID: func() string { return fixtureID(100 + int(f.newIDs.Add(1))) }}
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
func (f *investigationFixture) Resolve(_ context.Context, in privacy.Input) (privacy.Resolution, error) {
	r := identity.Revision{UID: fixtureID(9), Generation: 1, Digest: [32]byte{7}}
	set := privacy.PolicySet{Target: in.Target, Revision: r, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: f.policyGeneration, Digest: [32]byte{8}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 60, MaximumSeconds: 3600, DeletionBudgetSeconds: 10}}}
	return privacy.Resolve(set, in, f.now)
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
	a.MetadataValidUntil = identity.Earlier(q.Identity.ValidUntil, f.now.Add(5*time.Second))
	return a, ok, nil
}
func (f *investigationFixture) AdmitReviewedContext(_ context.Context, p value.ContextPreview, a value.Admission) (value.Accepted, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fixtureKey(a.Plan.Input.Executor, a.IdempotencyKey)
	if old, ok := f.accepted[key]; ok {
		old.Replay = true
		old.MetadataValidUntil = identity.Earlier(a.Eligibility.ValidUntil, f.now.Add(5*time.Second))
		return old, nil
	}
	if p.Actor != a.Plan.Input.Executor {
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
	out := value.Accepted{MetadataValidUntil: identity.Earlier(a.Eligibility.ValidUntil, f.now.Add(5*time.Second)), CaptureID: in.CaptureID, ScopeDigest: a.Plan.ScopeDigest, SubmissionDigest: a.SubmissionDigest, Expectation: e, Pin: t.Pin, CreatedAt: f.now, Deadline: in.Deadline}
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
	return f.svc.Request(context.Background(), f.source(t, context.Background()), reviewed(p, key))
}

// reviewed requests an already computed preview without a plan comparison.
func reviewed(p value.ContextPreview, key string) CaptureRequest {
	return CaptureRequest{Key: key, Preview: func(context.Context) (value.ContextPreview, error) { return p, nil }}
}

// requestDigest is the submission digest a request with key and no plan
// comparison derives for actor.
func requestDigest(s ContextInvestigation, actor identity.Principal, key string) artifact.Digest {
	_, _, _, d := s.requestScope(context.Background(), identity.Identity{Principal: actor}, CaptureRequest{Key: key})
	return d
}

func withAccess(p value.ContextPreview, key string, access *authorization.ResultAccess) CaptureRequest {
	r := reviewed(p, key)
	r.Access = access
	return r
}

func TestContextPreviewPassiveAndAssessment(t *testing.T) {
	f := newInvestigationFixture()
	r, err := f.svc.Preview(context.Background(), f.source(t, context.Background()), f.intent())
	if err != nil {
		t.Fatal(err)
	}
	if f.admissions.Load() != 0 || len(f.accepted) != 0 || !ValidContextPreview(r.Preview) {
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
	for _, key := range []string{"Identity", "VerifiedIdentity", "Proof", "Assessment", "AnchorAt", "ExpiresAt"} {
		if _, ok := object[key]; ok {
			t.Fatalf("persisted runtime authority %s", key)
		}
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
	f.cap.Enabled = false
	f.store = ContextStorageObservation{}
	a, err := f.request(t, p, "original")
	if err != nil || !a.Replay || a.CaptureID != p.CaptureID || f.admissions.Load() != 1 || f.targetReads.Load() != beforeReads || f.newIDs.Load() != beforeIDs {
		t.Fatal("failed exact recovery without original acquisition facts", err)
	}
	f.denied = true
	if _, err = f.svc.Request(context.Background(), fixtureIdentityResolverHandle{f}, reviewed(p, "original")); err == nil {
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
	for name, change := range map[string]func(*investigationFixture, *value.ContextPreview){
		"pod replacement": func(f *investigationFixture, _ *value.ContextPreview) {
			f.target.Request.PodUID = "replacement"
			f.target.Pin.UID = "replacement"
		},
		"node reboot":      func(f *investigationFixture, _ *value.ContextPreview) { f.target.NodeBootID = fixtureID(33) },
		"collector":        func(f *investigationFixture, _ *value.ContextPreview) { f.cap.CollectorImageDigest[0]++ },
		"ceiling":          func(f *investigationFixture, _ *value.ContextPreview) { f.cap.Revision.Digest[0]++ },
		"retention":        func(f *investigationFixture, _ *value.ContextPreview) { f.policyGeneration++ },
		"audience":         func(f *investigationFixture, _ *value.ContextPreview) { f.audience.AssignmentID = fixtureID(34) },
		"allocation":       func(f *investigationFixture, _ *value.ContextPreview) { f.store.Selection.PoolRevision++ },
		"assessment rules": func(_ *investigationFixture, p *value.ContextPreview) { p.AssessmentRulesDigest[0]++ },
	} {
		t.Run(name, func(t *testing.T) {
			f := newInvestigationFixture()
			p := f.preview(t)
			change(f, &p)
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
	for _, stage := range []string{"storage read", "admission reply"} {
		t.Run(stage, func(t *testing.T) {
			f := newInvestigationFixture()
			expire := func() { f.now = f.now.Add(5 * time.Second) }
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
		other := reviewed(f.preview(t), "one")
		other.Plan = artifact.Digest{9}
		if _, err := f.svc.Request(context.Background(), f.source(t, context.Background()), other); !errors.Is(err, value.ErrConflict) || f.admissions.Load() != 1 {
			t.Fatal("another plan under the same key was not a conflict", err)
		}
	})
}

func TestContextRequiresProtectedAuthorityAndNoDetachedContext(t *testing.T) {
	t.Run("canceled owner", func(t *testing.T) {
		f := newInvestigationFixture()
		p := f.preview(t)
		ctx, cancel := context.WithCancel(context.Background())
		source := f.source(t, ctx)
		cancel()
		if _, err := f.svc.Request(context.Background(), source, reviewed(p, "one")); err == nil || f.admissions.Load() != 0 {
			t.Fatal("background detached original request")
		}
	})
}

func TestContextPreviewRefusesCallerReason(t *testing.T) {
	f := newInvestigationFixture()
	in := f.intent()
	reason := "caller supplied"
	in.Reason = &reason
	if _, err := f.svc.Preview(context.Background(), f.source(t, context.Background()), in); err == nil {
		t.Fatal("caller reason accepted")
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
				a, err = f.svc.Request(context.Background(), source, reviewed(p, "one"))
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
	} {
		t.Run(name, func(t *testing.T) {
			bad := p.Clone()
			mutate(&bad)
			if ValidContextPreview(bad) {
				t.Fatal("invalid preview integrity accepted")
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

// A namespace that capacity does not cover takes no new collection
// (specs/capacity.md); the resolver still resolves it for reads.
func TestContextPreviewRefusesNamespaceWithoutEvidence(t *testing.T) {
	f := newInvestigationFixture()
	f.target.EvidenceDisabled = true
	_, err := f.svc.Preview(context.Background(), f.source(t, context.Background()), f.intent())
	if !errors.Is(err, targets.ErrEvidenceDisabled) || f.admissions.Load() != 0 {
		t.Fatal(err)
	}
}
