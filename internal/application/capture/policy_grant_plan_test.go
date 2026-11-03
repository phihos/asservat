package capture

import (
	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/syscalls"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	planning "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type acceptedGrantPlanFixture struct {
	before   func()
	snapshot authorization.AcceptedPolicySnapshot
	record   value.PolicyAcceptance
}

func (f *acceptedGrantPlanFixture) AcceptedPolicyRecord(context.Context, string) (authorization.AcceptedPolicySnapshot, value.PolicyAcceptance, error) {
	if f.before != nil {
		f.before()
	}
	return f.snapshot, f.record, nil
}

type grantPlanDocumentFunc func(context.Context, string, string) (value.PolicySource, []byte, error)

func (f grantPlanDocumentFunc) ReadPolicy(ctx context.Context, name, uid string) (value.PolicySource, []byte, error) {
	return f(ctx, name, uid)
}

func newPolicyGrantPlanFixture(t *testing.T) (*workloadActivationFixture, *acceptedGrantPlanFixture, PolicyGrantPlans) {
	t.Helper()
	f, activation := newWorkloadActivationFixture(t)
	if _, err := activation.Activate(context.Background(), f, "restarts", "first", true); err != nil {
		t.Fatal(err)
	}
	in := f.accepted[0]
	source, _, _ := f.ReadPolicy(context.Background(), "restarts", "policy-uid")
	record := value.PolicyAcceptance{ID: "99999999-9999-4999-8999-999999999999", RootID: activationRoot, Source: source, Submission: in.Submission, Authority: in.Authority, Submitter: f.author.Principal, IdentityRevision: f.author.Policy, PermissionRevision: f.projection.Revision, Recovery: in.Recovery, IntentVersion: 1, AcceptedAt: f.now}
	if !record.Valid() {
		t.Fatal("invalid accepted fixture")
	}
	accepted := &acceptedGrantPlanFixture{snapshot: authorization.AcceptedPolicySnapshot{Authority: record.Authority, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second), SourceUntil: source.FreshUntil}, record: record}
	plans := PolicyGrantPlans{Accepted: accepted, Documents: f, Sources: f, CompileRecorder: testPolicyRecorderCompiler, RecipeName: "builtin-pod-status-v1", RecipeDigest: testRecipe, Now: func() time.Time { return f.now }}
	return f, accepted, plans
}

func TestPolicyGrantPlanRebuildsOnlyExactAcceptedWorkloadScope(t *testing.T) {
	_, accepted, plans := newPolicyGrantPlanFixture(t)
	p, err := plans.PolicyGrantPlan(context.Background(), "policy-uid", "restarts")
	if err != nil || sha256.Sum256(p.Scope) != accepted.record.Authority.ScopeDigest || p.Authority.PolicyUID != "policy-uid" || p.RecipeDigest == (artifact.Digest{}) || p.Review.PodName != "" || p.Review.WorkloadKind != "Deployment" || len(p.Review.Actions) != 1 || p.Review.Actions[0].Kind != "packetCapture" || len(p.Reasons) != 1 || p.Reasons[0].Code != "policyCollection" {
		t.Fatal("exact policy review", p, err)
	}
	if p.DataClass != "extract" || p.Review.ObservationLimits != nil {
		t.Fatal("ordinary packet review changed", p)
	}
	if p.FreshUntil != accepted.snapshot.FreshUntil || p.Review.Deadline != accepted.record.Authority.NotAfter {
		t.Fatal("review renewed authority or freshness")
	}
}

func TestPolicyGrantPlanRefusesChangedInterpretationAndUnavailableAuthority(t *testing.T) {
	for _, name := range []string{"unknown-policy", "changed-recipe", "deleted-source", "wrong-source-name", "changed-collection", "expired-acceptance", "mismatched-authority", "lost-request"} {
		t.Run(name, func(t *testing.T) {
			f, accepted, plans := newPolicyGrantPlanFixture(t)
			policy := "policy-uid"
			ctx := context.Background()
			switch name {
			case "unknown-policy":
				policy = "other-policy"
			case "changed-recipe":
				edit := f.edit
				f.edit = func(s map[string]any) { edit(s); s["profileComposition"].(map[string]any)["maxDuration"] = "30s" }
			case "deleted-source", "wrong-source-name", "changed-collection":
				plans.Documents = grantPlanDocumentFunc(func(ctx context.Context, nameArg, uid string) (value.PolicySource, []byte, error) {
					s, b, e := f.ReadPolicy(ctx, nameArg, uid)
					if name == "deleted-source" {
						s.Deleted = true
					}
					if name == "wrong-source-name" {
						s.Name = "other"
					}
					if name == "changed-collection" {
						s.CollectionDigest[0]++
					}
					return s, b, e
				})
			case "expired-acceptance":
				accepted.snapshot.FreshUntil = f.now
			case "mismatched-authority":
				accepted.snapshot.Authority.NotAfter = accepted.snapshot.Authority.NotAfter.Add(-time.Second)
			case "lost-request":
				call, cancel := context.WithCancel(ctx)
				cancel()
				ctx = call
			}
			if _, err := plans.PolicyGrantPlan(ctx, policy, "restarts"); !errors.Is(err, authapp.ErrGrantUnavailable) {
				t.Fatal("changed/unavailable plan supplied", err)
			}
		})
	}
}

type grantPlanSourceFunc func(context.Context, value.PolicySource) error

func (f grantPlanSourceFunc) ObservePolicy(ctx context.Context, source value.PolicySource) error {
	return f(ctx, source)
}
func TestPolicyGrantNamedSourceRefreshPrecedesExpiredSQLAcceptanceRead(t *testing.T) {
	f, accepted, plans := newPolicyGrantPlanFixture(t)
	original := accepted.record.Authority
	// The protected source was last seen before a >30s outage; the independent
	// current recovery reader still supplies its ordinary five-second preflight.
	f.now = f.now.Add(31 * time.Second)
	observed := false
	accepted.before = func() {
		if !observed {
			t.Fatal("expired SQL read happened before actual protected source observation")
		}
	}
	plans.Sources = grantPlanSourceFunc(func(ctx context.Context, source value.PolicySource) error {
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(source.FreshUntil) {
			t.Fatal("source write renewed original read deadline")
		}
		observed = true
		accepted.snapshot.ObservedAt = source.ObservedAt
		accepted.snapshot.FreshUntil = identity.Earlier(source.FreshUntil, f.now.Add(5*time.Second))
		accepted.snapshot.SourceUntil = source.FreshUntil
		return nil
	})
	result, err := plans.PolicyGrantPlan(context.Background(), "policy-uid", "restarts")
	if err != nil || !observed || result.Authority.ScopeDigest != original.ScopeDigest || !result.Authority.NotAfter.Equal(original.NotAfter) || result.Authority.Limits != original.Limits || !result.FreshUntil.Equal(f.now.Add(5*time.Second)) {
		t.Fatal("named fresh request could not resolve original accepted authority", result, err)
	}
	accepted.before = func() { t.Fatal("source write failure fell back to SQL authority") }
	plans.Sources = grantPlanSourceFunc(func(context.Context, value.PolicySource) error { return value.ErrUnavailable })
	if _, err := plans.PolicyGrantPlan(context.Background(), "policy-uid", "restarts"); !errors.Is(err, authapp.ErrGrantUnavailable) {
		t.Fatal("unacknowledged source observation became fresh", err)
	}
}

// This compiler resolves the release's actual closed table without loading BPF.
type grantPlanArgumentCompiler struct {
	stubFilters
	changed bool
}

func (c *grantPlanArgumentCompiler) CompileArguments(names []string, buffers bool, width int64) (artifact.RecordingArguments, error) {
	defs, err := syscalls.ArgumentDefinitions(names, buffers, int(width))
	if err != nil {
		return artifact.RecordingArguments{}, err
	}
	a := artifact.RecordingArguments{DefinitionDigest: artifact.Digest(syscalls.ArgumentDefinitionDigest(defs)), AccountingRule: artifact.Digest(collector.ArgumentObservationAccountingRule()), MaxProbeBytes: int64(syscalls.ArgumentMaxProbeBytes(defs)), MaxBytesPerEvent: width, MaxBytesPerSecond: planning.SensitiveMaxBytesPerSecond, CaptureBuffers: buffers}
	raw, _ := hex.DecodeString(gadget.ArgumentObjectSHA256)
	copy(a.ProgramDigest[:], raw)
	if c.changed {
		a.DefinitionDigest[0]++
	}
	return a, nil
}
func argumentGrantPlanFixture(t *testing.T, events int64) (*workloadActivationFixture, *acceptedGrantPlanFixture, PolicyGrantPlans, *grantPlanArgumentCompiler) {
	t.Helper()
	f, accepted, plans := newPolicyGrantPlanFixture(t)
	raw, err := os.ReadFile("../planning/profiles/syscall-activity-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["name"] = "argument-capture"
	recipe := doc["definition"].(map[string]any)["recipe"].(map[string]any)
	action := recipe["actions"].([]any)[0].(map[string]any)
	action["impact"], action["executionMode"] = "sensitiveRead", "onTrigger"
	action["limits"].(map[string]any)["maxBytes"] = 8 << 20
	params := action["parameters"].(map[string]any)
	params["mode"], params["before"], params["after"] = "arguments", "0s", "3s"
	params["maxFrozenBytes"] = 8 << 20
	params["syscalls"] = map[string]any{"mode": "include", "names": []string{"openat"}}
	params["arguments"] = map[string]any{"maxBytesPerEvent": 128, "captureBuffers": false}
	recipe["maxTotalBytes"] = 8 << 20
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	mechanism := &grantPlanArgumentCompiler{}
	plans.CompileRecorder = SingleRecorder(func(b json.RawMessage) (planning.PolicyRecorderConfiguration, error) {
		var wire contracts.CaptureComposition
		if err := json.Unmarshal(b, &wire); err != nil {
			return planning.PolicyRecorderConfiguration{}, err
		}
		c, err := conversion.CompositionFromWire(wire)
		if err != nil {
			return planning.PolicyRecorderConfiguration{}, err
		}
		c.Resolved = []planning.CatalogProfile{{Ref: c.Components[0].Profile, SourceClusterID: activationCluster, SourceNamespaceUID: "ns-uid", SourceUID: "argument-profile", Document: raw, Enabled: true}}
		return compiler.CompilePolicyRecorder(*c, mechanism)
	})
	edit := f.edit
	f.edit = func(s map[string]any) {
		edit(s)
		s["profileComposition"] = map[string]any{"components": []any{map[string]any{"id": "calls", "profileRef": map[string]any{"catalog": "namespace", "name": "argument-capture", "version": "v1"}}}, "maxTotalBytes": 8 << 20, "maxDuration": "30s"}
	}
	source, spec, _ := f.ReadPolicy(t.Context(), "restarts", "policy-uid")
	compiled, err := CompilePolicyWithRecorders(context.Background(), targets.Request{}, spec, plans.RecipeName, plans.RecipeDigest, plans.CompileRecorder)
	if err != nil {
		t.Fatal(err)
	}
	a := accepted.record.Authority
	a.Actions = []string{"syscallTrace"}
	a.Limits.MaxObservedBytes = 128 << 20
	a.Limits.MaxObservedEvents = events // aggregate pool covers more than one 40000-unit capture
	a.ScopeDigest = RecorderPolicyScopeDigest(source.Revision.UID, accepted.record.IntentVersion, source.CollectionDigest, compiled, a.NamespaceUID, a.WorkloadUID, a.Delegation, a.Owners, a.Actions, a.Limits)
	accepted.record.Authority, accepted.snapshot.Authority = a, a
	accepted.record.Submission.ScopeDigest = a.ScopeDigest
	if !accepted.record.Valid() {
		t.Fatal("invalid synthetic accepted argument scope")
	}
	return f, accepted, plans, mechanism
}
func TestPolicyGrantPlanReviewsFiniteArgumentsAsRawWithSharedEventPool(t *testing.T) {
	_, accepted, plans, _ := argumentGrantPlanFixture(t, 80000)
	p, err := plans.PolicyGrantPlan(t.Context(), "policy-uid", "restarts")
	if err != nil {
		t.Fatal(err)
	}
	if p.DataClass != "raw" || !slices.ContainsFunc(p.Reasons, func(r authorization.SensitiveReason) bool { return r.Code == planning.ReasonSyscallArguments }) {
		t.Fatal("argument paths were not reviewed as raw", p.DataClass, p.Reasons)
	}
	want := authapp.GrantObservationLimits{MaxSessionSeconds: 13, MaxObservedBytes: 128 << 20, MaxBytesPerSecond: planning.SensitiveMaxBytesPerSecond, MaxConcurrentSessions: 1, MaxObservedEvents: 80000}
	if p.Review.ObservationLimits == nil || *p.Review.ObservationLimits != want {
		t.Fatalf("shared argument pool changed: got=%+v want=%+v", p.Review.ObservationLimits, want)
	}
	if p.FreshUntil != accepted.snapshot.FreshUntil || p.Review.Deadline != accepted.record.Authority.NotAfter || sha256.Sum256(p.Scope) != accepted.record.Authority.ScopeDigest {
		t.Fatal("review changed original authority")
	}
}
func TestPolicyGrantPlanRefusesChangedArgumentMechanism(t *testing.T) {
	_, _, plans, mechanism := argumentGrantPlanFixture(t, 80000)
	mechanism.changed = true
	if _, err := plans.PolicyGrantPlan(t.Context(), "policy-uid", "restarts"); !errors.Is(err, authapp.ErrGrantUnavailable) {
		t.Fatal("changed trusted definition reused acceptance", err)
	}
}

func TestPolicyGrantPlanRefusesArgumentsWithoutAcceptedEventPool(t *testing.T) {
	_, _, plans, _ := argumentGrantPlanFixture(t, 0)
	if _, err := plans.PolicyGrantPlan(t.Context(), "policy-uid", "restarts"); !errors.Is(err, authapp.ErrGrantUnavailable) {
		t.Fatal("zero aggregate event ceiling authorized arguments", err)
	}
}
