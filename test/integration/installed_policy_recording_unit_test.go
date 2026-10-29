package integration

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/transport/conversion"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The real installed hub uses libpcap. This exact program is solely the offline
// compiler input for preflighting the authored request; no capture can use it.
// The fixture was emitted by the maintained libpcap dead-handle compiler; the
// libpcap-tagged test compares every instruction against a fresh compilation.
type installedPolicyRecordingFilters struct{}

func TestInstalledPolicyRecordingReviewInputs(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	const id = "11111111-1111-4111-8111-111111111111"
	decision := installedPolicyRecordingDecisionArguments(id)
	raw, _ := json.Marshal(decision)
	if err = wire.ValidateInput("decide_review", raw); err != nil {
		t.Fatal("actual native policy decision disagrees with closed production input", err)
	}
	revoke := installedPolicyRecordingRevocationArguments(id, 2)
	raw, _ = json.Marshal(revoke)
	if err = wire.ValidateInput("revoke_grant", raw); err != nil {
		t.Fatal("actual native policy revocation disagrees with production CAS input", err)
	}
	decision["expected_revision"] = 1
	raw, _ = json.Marshal(decision)
	if wire.ValidateInput("decide_review", raw) == nil {
		t.Fatal("decision contract silently accepted a revocation-only field")
	}
	delete(revoke, "expected_revision")
	raw, _ = json.Marshal(revoke)
	if wire.ValidateInput("revoke_grant", raw) == nil {
		t.Fatal("revocation lost its required original revision")
	}
}

// Validate the actual installed request against the shipped structural CRD,
// rather than only the richer offline JSON contract. This opens no API/collector.
func TestInstalledPolicyRecordingProductionCRD(t *testing.T) {
	raw, err := os.ReadFile("../../charts/asservat/crds/debugpolicies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var crd map[string]any
	if err = json.Unmarshal(raw, &crd); err != nil {
		t.Fatal(err)
	}
	version := crd["spec"].(map[string]any)["versions"].([]any)[0].(map[string]any)
	structural := version["schema"].(map[string]any)["openAPIV3Schema"]
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err = c.AddResource("urn:production-debug-policy", structural); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("urn:production-debug-policy")
	if err != nil {
		t.Fatal(err)
	}
	spec := installedPolicyRecordingSpec("11111111-1111-4111-8111-111111111111", "payments", "api")
	document := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "DebugPolicy", "metadata": map[string]any{"name": installedPolicyRecordingName}, "spec": spec}
	// Roundtrip normalizes integer representations just as Kubernetes JSON does.
	raw, _ = json.Marshal(document)
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if err = schema.Validate(document); err != nil {
		t.Fatal("shipped structural CRD rejects the actual finite policy request", err)
	}
	properties := structural.(map[string]any)["properties"].(map[string]any)["spec"].(map[string]any)["properties"].(map[string]any)
	if properties["profileComposition"] == nil {
		t.Fatal("Kubernetes would prune the policy composition as an unknown field")
	}
	if properties["grantRef"] == nil {
		t.Fatal("Kubernetes would prune authored grant-reference changes before source continuity checks")
	}
	var ordinary map[string]any
	_ = json.Unmarshal(raw, &ordinary)
	ordinarySpec := ordinary["spec"].(map[string]any)
	delete(ordinarySpec, "profileComposition")
	ordinarySpec["recipeRef"] = map[string]any{"name": "builtin-pod-status-v1", "digest": strings.Repeat("a", 64)}
	ordinarySpec["grantRef"] = "11111111-1111-4111-8111-111111111111"
	if err = schema.Validate(ordinary); err != nil {
		t.Fatal("structural update broke existing recipe policy shape", err)
	}
	for _, item := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"both recipe and composition", func(s map[string]any) {
			s["recipeRef"] = map[string]any{"name": "builtin-pod-status-v1", "digest": strings.Repeat("a", 64)}
		}},
		{"neither recipe nor composition", func(s map[string]any) { delete(s, "profileComposition") }},
		{"malformed grant reference", func(s map[string]any) { s["grantRef"] = "not-a-uuid" }},
		{"component limit", func(s map[string]any) {
			c := s["profileComposition"].(map[string]any)
			component := c["components"].([]any)[0]
			items := make([]any, 9)
			for i := range items {
				items[i] = component
			}
			c["components"] = items
		}},
		{"override discriminator", func(s map[string]any) {
			c := s["profileComposition"].(map[string]any)["components"].([]any)[0].(map[string]any)
			c["overrides"].([]any)[0].(map[string]any)["field"] = "unknown"
		}},
		{"override limit", func(s map[string]any) {
			c := s["profileComposition"].(map[string]any)["components"].([]any)[0].(map[string]any)
			edit := c["overrides"].([]any)[0]
			items := make([]any, 33)
			for i := range items {
				items[i] = edit
			}
			c["overrides"] = items
		}},
		{"total byte limit", func(s map[string]any) { s["profileComposition"].(map[string]any)["maxTotalBytes"] = float64(1<<40) + 1 }},
	} {
		t.Run(item.name, func(t *testing.T) {
			var changed map[string]any
			_ = json.Unmarshal(raw, &changed)
			item.edit(changed["spec"].(map[string]any))
			if schema.Validate(changed) == nil {
				t.Fatal("production structural schema admitted invalid composition")
			}
		})
	}
	// Heterogeneous override values must survive CRD pruning unchanged. Their
	// field-specific closed validation remains in the production source reader's
	// embedded canonical schema, before compilation or accepted authority.
	canonical := jsonschema.NewCompiler()
	canonical.AssertFormat()
	files, err := filepath.Glob("../../internal/adapters/kubernetes/policy-schemas/*.json")
	if err != nil || len(files) == 0 {
		t.Fatal("canonical source schemas", err)
	}
	for _, file := range files {
		body, err := os.ReadFile(file)
		var doc map[string]any
		if err != nil || json.Unmarshal(body, &doc) != nil || canonical.AddResource(doc["$id"].(string), doc) != nil {
			t.Fatal("canonical source schema", file, err)
		}
	}
	closed, err := canonical.Compile("https://asservat.io/spec/v1/policy.schema.json#/properties/spec")
	if err != nil || closed.Validate(document["spec"]) != nil {
		t.Fatal("actual request disagrees with canonical source reader", err)
	}
	component := document["spec"].(map[string]any)["profileComposition"].(map[string]any)["components"].([]any)[0].(map[string]any)
	component["overrides"].([]any)[0].(map[string]any)["value"] = map[string]any{"unreviewed": true}
	if closed.Validate(document["spec"]) == nil {
		t.Fatal("canonical source reader admitted wrong typed override value")
	}
}

func (installedPolicyRecordingFilters) CompileFilter(expression string) (value.CompiledFilter, error) {
	if expression != installedPolicyRecordingFilter {
		return value.CompiledFilter{}, value.ErrInvalid
	}
	raw, err := os.ReadFile("../../internal/adapters/pcap/testdata/finite-policy-ack-filter.json")
	if err != nil {
		return value.CompiledFilter{}, err
	}
	var fixture struct {
		Expression, Compiler string
		Filter               value.CompiledFilter
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		return value.CompiledFilter{}, err
	}
	if fixture.Expression != expression || !strings.HasPrefix(fixture.Compiler, "libpcap version 1.11.0 ") {
		return value.CompiledFilter{}, value.ErrInvalid
	}
	return fixture.Filter, nil
}

func TestInstalledPolicyRecordingAuthoredInputs(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	const uid = "11111111-1111-4111-8111-111111111111"
	input := installedPolicyRecordingGrantArguments(uid, "installed-policy-grant")
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err = wire.ValidateInput("request_policy_grant", raw); err != nil {
		t.Fatal("real native grant request schema", err)
	}
	for _, name := range []string{"capture_id", "pod_uid", "scope", "authority", "requester", "result_access"} {
		changed := installedPolicyRecordingGrantArguments(uid, "closed-input")
		changed[name] = "invented"
		raw, _ = json.Marshal(changed)
		if wire.ValidateInput("request_policy_grant", raw) == nil {
			t.Fatal("request accepted caller-selected authority", name)
		}
	}
	raw, _ = json.Marshal(installedPolicyRecordingSpec(uid, "payments", "api"))
	compile := func(raw json.RawMessage) (value.PolicyRecorderConfiguration, error) {
		var composition contracts.CaptureComposition
		if err := json.Unmarshal(raw, &composition); err != nil {
			return value.PolicyRecorderConfiguration{}, err
		}
		in, err := conversion.CompositionFromWire(composition)
		if err != nil || in == nil {
			return value.PolicyRecorderConfiguration{}, value.ErrInvalid
		}
		return compiler.CompilePolicyRecorder(*in, installedPolicyRecordingFilters{})
	}
	plan, err := captureapp.CompilePolicyWithRecorders(raw, compiler.ContextRecipeName, compiler.RecipeDigest(), compile)
	if err != nil || plan.Recorder == nil || plan.Recorder.Action.ExecutionMode != "onTrigger" || plan.Recorder.Action.Before != "0s" || plan.Recorder.Action.After != "2s" || plan.Recorder.Action.Filter != installedPolicyRecordingFilter || plan.Recorder.Filter == nil {
		t.Fatal("native authored finite policy plan", err)
	}
	if err = packets.CheckPrefixProgram(plan.Recorder.Filter.Program); err != nil {
		t.Fatal("native reviewed program exceeds actual prefix", err)
	}
	// The public policy grant review derives its session ceiling from this
	// exact authored action timeout. A schema-valid larger request would still
	// be refused by RequestPolicy; catch it before an installed runner starts.
	timeout, err := time.ParseDuration(plan.Recorder.Action.Timeout)
	observation := input["observation_limits"].(map[string]any)
	if err != nil || int64(observation["max_session_seconds"].(int))*int64(time.Second) > int64(timeout) {
		t.Fatal("native grant exceeds original action review", observation, plan.Recorder.Action.Timeout, err)
	}
	// RequestPolicy validates a pending Grant with Grant.Valid before any
	// store effect. Exercise that same production scope validation, rather
	// than treating JSON-schema acceptance as a usable grant request.
	_, fixture := newConsoleManagerGrants(t, "https://console.invalid")
	for _, name := range []string{"normal", "tiny", "mismatched"} {
		t.Run(name, func(t *testing.T) {
			args := installedPolicyRecordingGrantArguments(uid, "native-"+name)
			limits := args["limits"].(map[string]any)
			observed := args["observation_limits"].(map[string]any)
			if name == "tiny" {
				limits["max_observed_bytes"], observed["max_observed_bytes"] = 1, 1
			}
			if name == "mismatched" {
				limits["max_observed_bytes"] = observed["max_observed_bytes"].(int) + 1
			}
			g := fixture.g
			policy := g.Policy.Clone()
			g.Policy = &policy
			// Reuse synthetic accepted identity/owner/settings facts, but bind
			// the genuine authored recorder scope and original installed envelope.
			a := &g.Policy.Authority
			a.PolicyUID, a.ClusterID = uid, uid
			a.Executor = authorization.PolicyPrincipal(a.InstallationID, uid)
			a.Limits = authorization.AutomationLimits{MaxExecutions: 2, MaxBytes: 16 << 20, MaxObservedBytes: 128 << 20}
			g.Scope = captureapp.RecorderPolicyScope(uid, 1, artifact.Digest{1}, plan, a.NamespaceUID, a.WorkloadUID, a.Delegation, a.Owners, a.Actions, a.Limits)
			a.ScopeDigest = sha256.Sum256(g.Scope)
			g.ExecutionDigest = a.ScopeDigest
			g.Policy.RecipeDigest = compiler.RecipeDigest()
			g.Policy.Limits = authorization.AutomationLimits{MaxExecutions: int64(limits["max_executions"].(int)), MaxBytes: int64(limits["max_collected_bytes"].(int)), MaxObservedBytes: int64(limits["max_observed_bytes"].(int))}
			g.Policy.Observation = &authorization.ObservationLimits{MaxSessionSeconds: int64(observed["max_session_seconds"].(int)), MaxObservedBytes: int64(observed["max_observed_bytes"].(int)), MaxBytesPerSecond: int64(observed["max_bytes_per_second"].(int)), MaxConcurrentSessions: int64(observed["max_concurrent_sessions"].(int))}
			g.Lifetime = time.Duration(args["lifetime_seconds"].(int)) * time.Second
			g.PolicyNotAfter = g.RequestedAt.Add(g.Lifetime)
			g.Decision, g.ExpiresAt, g.Revision = nil, time.Time{}, 1
			g.PolicySpend = authorization.PolicyGrantSpend{}
			g.ReviewDigest = authapp.ReviewDigest(g, g.Review)
			if len(g.Scope) == 0 || g.Valid() != (name != "mismatched") {
				t.Fatalf("authored grant pre-store validation: valid=%t total=%d observation=%d", g.Valid(), g.Policy.Limits.MaxObservedBytes, g.Policy.Observation.MaxObservedBytes)
			}
		})
	}
}

func TestInstalledPolicyRecordingNativeFieldProof(t *testing.T) {
	for _, item := range []struct {
		input string
		count int
		class string
	}{
		{"1\tTrue\t\n", 1, ""}, {"1\tTrue\t\n2\tTrue\t\n", 2, ""}, {"", 0, ""},
		{"1\tTrue\t616263\n", 0, "payload"}, {"1\t1\t\n", 0, "ack"}, {"\tTrue\t\n", 0, "frame-number"},
		{"1\tTrue\t\textra\n", 0, "columns"}, {"1\tFalse\t\n", 0, "ack"}, {"1\tTrue\n", 0, "columns"},
	} {
		got, err := policyRecordingPacketFields([]byte(item.input))
		if (err != nil) != (item.class != "") || got != item.count {
			t.Fatalf("native fields count=%d err=%v want=%d/class=%s", got, err, item.count, item.class)
		}
		if err != nil && (strings.Contains(err.Error(), "616263") || !strings.Contains(err.Error(), "row 1 ("+item.class+")")) {
			t.Fatal("field failure lost its closed row evidence or rendered payload")
		}
	}
}

func TestInstalledPolicyRecordingCreditRefusalProof(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	const reason = "node collector: capture " + id + " stopped: ObservationBudgetExhausted"
	for _, item := range []struct {
		name, log string
		want      bool
	}{
		{"exact", reason + "\n", true},
		{"logger timestamp", "2026/10/28 06:00:00 " + reason + "\n", true},
		{"generic capture failure", "node collector: capture " + id + " stopped: CaptureFailed\n", false},
		{"source failure", "node collector: capture " + id + " stopped: ObservationClosed\n", false},
		{"provider failure", "node collector: capture " + id + " stopped: target not found\n", false},
		{"different capture", strings.ReplaceAll(reason, id, "22222222-2222-4222-8222-222222222222"), false},
		{"partial reason", reason + "Extra", false},
		{"none", "", false},
	} {
		t.Run(item.name, func(t *testing.T) {
			if got := policyRecordingCreditRefusal([]byte(item.log), id); got != item.want {
				t.Fatalf("capture-specific input credit proof=%t want=%t", got, item.want)
			}
		})
	}
}
