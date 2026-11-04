package capture

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	planning "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
)

func newProfileGrantPlanFixture(t *testing.T) (*workloadActivationFixture, *acceptedGrantPlanFixture, PolicyGrantPlans) {
	t.Helper()
	f, activation := newWorkloadActivationFixture(t)
	f.envelope.AllowedActions, f.envelope.MaxBytes = []string{"profile"}, 64<<20
	edit := f.edit
	f.edit = func(spec map[string]any) {
		edit(spec)
		spec["profileComposition"] = map[string]any{"components": []any{map[string]any{"id": "cpu", "profileRef": map[string]string{"catalog": "builtin", "name": "go-cpu", "version": "v1"}}}, "maxTotalBytes": 16 << 20, "maxDuration": "30s"}
	}
	definition := planning.GoEndpointDefinition{Source: planning.GoEndpointSource{ClusterID: activationCluster, ResourceUID: "10000000-0000-4000-8000-000000000001", Name: "go-pprof-loopback", Digest: artifact.Digest{17}}, Host: "localhost", PathPolicy: planning.GoEndpointPathPolicy, AddressModes: []string{"targetLoopback"}, MinimumPort: 6000, MaximumPort: 6999, LoopbackFamily: "ipv4"}
	definitionDigest, err := compiler.ProfileEndpointDefinitionDigest(definition)
	if err != nil {
		t.Fatal(err)
	}
	compile := func(_ context.Context, _ targets.Request, raw json.RawMessage) ([]planning.PolicyRecorderConfiguration, error) {
		var wire contracts.CaptureComposition
		if err := json.Unmarshal(raw, &wire); err != nil {
			return nil, err
		}
		composition, err := conversion.CompositionFromWire(wire)
		if err != nil {
			return nil, err
		}
		_, err = compiler.CompilePolicyRecorder(*composition, nil)
		var needed compiler.PolicyProfileEndpointNeeded
		if !errors.As(err, &needed) || len(needed.Bindings) != 1 {
			return nil, planning.ErrInvalid
		}
		binding := needed.Bindings[0]
		pin := &planning.PolicyProfileEndpoint{Definition: definition, DefinitionDigest: definitionDigest, SourceRef: needed.SourceRef, SourceKind: targets.ProfileEndpointTemplateBinding, AddressMode: binding.AddressMode, Binding: &binding}
		cfg, err := compiler.CompilePolicyRecorder(*composition, nil, pin)
		return []planning.PolicyRecorderConfiguration{cfg}, err
	}
	activation.CompileRecorder = compile
	if _, err := activation.Activate(t.Context(), f, "restarts", "profile", true); err != nil {
		t.Fatal("actual profile policy compiler/acceptance", err)
	}
	in := f.accepted[0]
	source, _, _ := f.ReadPolicy(t.Context(), "restarts", "policy-uid")
	record := value.PolicyAcceptance{ID: "99999999-9999-4999-8999-999999999999", RootID: activationRoot, Source: source, Submission: in.Submission, Authority: in.Authority, Submitter: f.author.Principal, IdentityRevision: f.author.Policy, PermissionRevision: f.projection.Revision, Recovery: in.Recovery, IntentVersion: 1, AcceptedAt: f.now}
	if !record.Valid() {
		t.Fatal("profile acceptance fixture invalid")
	}
	accepted := &acceptedGrantPlanFixture{snapshot: authorization.AcceptedPolicySnapshot{Authority: record.Authority, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second), SourceUntil: source.FreshUntil}, record: record}
	return f, accepted, PolicyGrantPlans{Accepted: accepted, Documents: f, Sources: f, CompileRecorder: compile, Now: func() time.Time { return f.now }}
}

func TestPolicyProfileGrantReviewHasStableDefinitionAndNoObservation(t *testing.T) {
	_, _, plans := newProfileGrantPlanFixture(t)
	p, err := plans.PolicyGrantPlan(t.Context(), "policy-uid", "restarts")
	if err != nil || p.DataClass != "raw" || p.Review.ObservationLimits != nil || p.MaxStartsPerExecution != 0 || len(p.Review.Actions) != 1 {
		t.Fatal("profile review contract", p, err)
	}
	a := p.Review.Actions[0]
	if a.Kind != "profile" || a.Before != "" || a.After != "" || a.RingMaxBytes != 0 || a.Profile == nil || a.Profile.Type != "cpu" || a.Profile.Duration != "10s" || a.Profile.Timeout != "15s" || a.Profile.Port != 0 || a.Profile.DeclaredPortName != "diagnostics" || a.Profile.MinimumPort != 6000 || a.Profile.MaximumPort != 6999 || len(a.Profile.DefinitionDigest) != 64 || a.Profile.EndpointDigest != "" {
		t.Fatal("review invented a concrete endpoint or packet window", a)
	}
	g := authorization.Grant{Kind: authorization.GrantPolicy, ExecutionDigest: p.Authority.ScopeDigest, DataClass: p.DataClass, Scope: p.Scope, Reasons: p.Reasons, Policy: &authorization.PolicyGrantScope{Authority: p.Authority, RecipeDigest: p.RecipeDigest, Limits: authorization.AutomationLimits{MaxExecutions: 2, MaxBytes: 32 << 20}}}
	if _, err := authapp.PolicyProfileGrantRecorder(g); err != nil {
		t.Fatal("complete compiled parent scope refused", err)
	}
	for name, mutate := range map[string]func(*authorization.Grant){
		"scope payload": func(g *authorization.Grant) { g.Scope = append(append([]byte{}, g.Scope...), ' ') },
		"missing raw":   func(g *authorization.Grant) { g.DataClass = "extract" },
		"missing live reason": func(g *authorization.Grant) {
			g.Reasons = []authorization.SensitiveReason{{ActionID: a.ActionID, Code: "policyCollection"}}
		},
		"missing policy reason": func(g *authorization.Grant) {
			g.Reasons = []authorization.SensitiveReason{{ActionID: a.ActionID, Code: planning.ReasonLiveProfile}}
		},
		"wrong action reason": func(g *authorization.Grant) {
			g.Reasons = []authorization.SensitiveReason{{ActionID: "different", Code: "policyCollection"}, {ActionID: "different", Code: planning.ReasonLiveProfile}}
		},
		"observed bytes":  func(g *authorization.Grant) { g.Policy.Limits.MaxObservedBytes = 1 },
		"observed events": func(g *authorization.Grant) { g.Policy.Limits.MaxObservedEvents = 1 },
		"observation":     func(g *authorization.Grant) { g.Policy.Observation = &authorization.ObservationLimits{} },
		"wrong recipe":    func(g *authorization.Grant) { g.Policy.RecipeDigest[0]++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := g
			policy := g.Policy.Clone()
			changed.Policy = &policy
			mutate(&changed)
			if _, err := authapp.PolicyProfileGrantRecorder(changed); err == nil {
				t.Fatal("incomplete or changed parent scope accepted")
			}
		})
	}
	encoded, _ := json.Marshal(p.Review)
	if strings.Contains(string(encoded), "EndpointDigest\":\""+strings.Repeat("0", 64)) {
		t.Fatal("unknown concrete endpoint represented as a known digest")
	}
}
