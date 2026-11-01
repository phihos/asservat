package capture

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
)

// Real private recorder compiler/scope, synthetic accepted/current authority.
// These tests do not establish SQL issuance, independent review or collection.
func compiledFanoutGrant(t *testing.T, optin bool, pods int, policySaves, grantStarts int64, declared int) authorization.Grant {
	t.Helper()
	cohort := newSourceCohortFixture(t, 2)
	p, a := cohort.policy, cohort.authority
	p.RecordingSaves = optin
	p.IncidentPods = pods
	a.Limits.MaxExecutions = policySaves
	scope := RecorderPolicyScope(a.PolicyUID, 1, artifact.Digest{99}, p, a.NamespaceUID, a.WorkloadUID, a.Delegation, a.Owners, a.Actions, a.Limits)
	if len(scope) == 0 {
		t.Fatal("valid actual compiled scope baseline")
	}
	a.ScopeDigest = sha256.Sum256(scope)
	now := cohort.f.now
	g := authorization.Grant{ID: fixtureID(8800), RootID: cohort.f.svc.RootID, Kind: authorization.GrantPolicy, ExecutionDigest: a.ScopeDigest, DataClass: "extract", Reasons: []authorization.SensitiveReason{{ActionID: p.Recorder.Action.ID, Code: "policyCollection"}}, Scope: scope, Review: []byte(`{}`), Requester: a.Creator, RequestedAt: now, ReviewUntil: now.Add(authorization.GrantReviewWindow), Lifetime: time.Hour, PolicyNotAfter: identity.Earlier(now.Add(time.Hour), a.NotAfter), Revision: 1, Policy: &authorization.PolicyGrantScope{Authority: a, RecipeDigest: p.Recorder.RecipeDigest, Limits: authorization.AutomationLimits{MaxExecutions: grantStarts, MaxBytes: a.Limits.MaxBytes}, ApprovalPolicyRef: identity.Revision{UID: "approval-settings", Generation: 1, Digest: artifact.Digest{7}}, ApprovalMaxAge: time.Hour, MaxStartsPerExecution: declared}}
	g.ReviewDigest = authapp.ReviewDigest(g, g.Review)
	return g
}

func TestPolicyGrantConvertsOneSaveToReviewedSourceStarts(t *testing.T) {
	g := compiledFanoutGrant(t, true, 2, 1, 2, 2)
	if g.Valid() {
		t.Fatal("unverified fanout supplied its own witness")
	}
	checked, err := authapp.BindReviewedPolicyGrantStarts(g)
	if err != nil || !checked.Valid() || checked.Policy.Authority.Limits.MaxExecutions != 1 || checked.Policy.Limits.MaxExecutions != 2 {
		t.Fatal("one Save cannot fund two individually reviewed starts", err)
	}
	for name, mutate := range map[string]func(*authorization.Grant){
		"scope":            func(x *authorization.Grant) { x.Scope = append([]byte(nil), x.Scope...); x.Scope[len(x.Scope)-1] ^= 1 },
		"fanout":           func(x *authorization.Grant) { x.Policy.MaxStartsPerExecution = 3 },
		"fanout removed":   func(x *authorization.Grant) { x.Policy.MaxStartsPerExecution = 0 },
		"authority digest": func(x *authorization.Grant) { x.Policy.Authority.ScopeDigest[0] ^= 1 },
		"authority budget": func(x *authorization.Grant) { x.Policy.Authority.Limits.MaxExecutions++ },
		"recipe":           func(x *authorization.Grant) { x.Policy.RecipeDigest[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			x := checked
			p := checked.Policy.Clone()
			x.Policy = &p
			mutate(&x)
			if x.Valid() {
				t.Fatal("mutated immutable witness accepted")
			}
		})
	}
	raw, err := json.Marshal(checked)
	if err != nil {
		t.Fatal(err)
	}
	var decoded authorization.Grant
	if json.Unmarshal(raw, &decoded) != nil || decoded.Valid() {
		t.Fatal("serialized fields carried a transient checked witness")
	}
	decoded, err = authapp.BindReviewedPolicyGrantStarts(decoded)
	if err != nil || !decoded.Valid() {
		t.Fatal("SQL/wire decoded checked scope cannot be rebound", err)
	}
}

func TestPolicyGrantFanoutCannotInventOptInOrRaiseExistingMaxima(t *testing.T) {
	for name, g := range map[string]authorization.Grant{
		"without opt-in":      compiledFanoutGrant(t, false, 0, 1, 2, 2),
		"cap one":             compiledFanoutGrant(t, true, 1, 1, 2, 2),
		"inflated fanout":     compiledFanoutGrant(t, true, 2, 1, 3, 3),
		"global ten thousand": compiledFanoutGrant(t, true, 16, 1000, 10001, 16),
	} {
		t.Run(name, func(t *testing.T) {
			checked, err := authapp.BindReviewedPolicyGrantStarts(g)
			if err == nil && checked.Valid() {
				t.Fatal("unreviewed/inflated start conversion accepted")
			}
		})
	}
	legacy := compiledFanoutGrant(t, true, 2, 1, 1, 0)
	if !legacy.Valid() {
		t.Fatal("legacy zero-fanout grant changed")
	}
	legacy.Policy.Limits.MaxExecutions = 2
	if legacy.Valid() {
		t.Fatal("old grant silently acquired new source-start units")
	}
}

func TestPolicyStatusGrantStartsUsesExistingAcceptedInputsAndOneLocalCompile(t *testing.T) {
	f, activation := newWorkloadActivationFixture(t)
	base := f.edit
	f.edit = func(spec map[string]any) {
		base(spec)
		spec["target"].(map[string]any)["maxPods"] = 2
		spec["recordingSaves"] = map[string]any{"enabled": true}
		spec["profileComposition"].(map[string]any)["components"].([]any)[0].(map[string]any)["overrides"] = []any{}
	}
	f.envelope.MaxExecutions = 1
	f.envelope.MaxObservedBytes = 1 << 30
	activation.CompileRecorder = ongoingSaveCompiler
	accepted, err := activation.Activate(t.Context(), f, "restarts", "status-multi-source", true)
	if err != nil {
		t.Fatal("actual opted-in cap2 policy acceptance", err)
	}
	a := f.accepted[0].Authority
	f.status = value.PolicyStatus{PolicyUID: a.PolicyUID, ActiveID: accepted.AcceptanceID, AcceptedIntentVersion: 1, Authority: a, NotAfter: a.NotAfter, MaxExecutions: a.Limits.MaxExecutions}
	calls := 0
	service := PolicyStatusService{RootID: activationRoot, InstallationID: activationInstallation, Documents: f, Ledger: f, Permissions: f.activationFixture, Recovery: f, Now: func() time.Time { return f.now }, RecipeName: "builtin-pod-status-v1", RecipeDigest: testRecipe, CompileRecorder: func(raw json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
		calls++
		return ongoingSaveCompiler(raw)
	}}
	originalObservations, originalAcceptances := len(f.observed), len(f.accepted)
	status, _, err := service.Get(t.Context(), f, "restarts")
	if err != nil || status.MaxGrantStarts != 2 || status.MaxExecutions != 1 || calls != 1 || len(f.observed) != originalObservations || len(f.accepted) != originalAcceptances {
		t.Fatal("status invented I/O, authority or unbounded source-start guidance", status.MaxGrantStarts, status.MaxExecutions, calls, err)
	}
	f.status.Authority.ScopeDigest[0] ^= 1
	status, _, err = service.Get(t.Context(), f, "restarts")
	if err != nil || status.MaxGrantStarts != 0 || calls != 2 {
		t.Fatal("changed accepted scope supplied widened grant guidance", status.MaxGrantStarts, calls, err)
	}
}
