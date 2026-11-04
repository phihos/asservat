package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	captureapp "asservat.local/asservat/internal/application/capture"
	planningapp "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	planning "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// This preflight exercises the actual authored profile and policy through the
// production planner. Catalog identity here is explicitly synthetic; only the
// installed flow supplies protected source observations and approval authority.
func TestInstalledPolicyArgumentsInputsCompile(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	definition, err := manualArgumentsProfileDefinition()
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(map[string]any{"name": manualArgumentsProfile, "version": "v1", "definition": definition})
	compile := func(_ context.Context, _ targets.Request, raw json.RawMessage) ([]planning.PolicyRecorderConfiguration, error) {
		var wire contracts.CaptureComposition
		if err := json.Unmarshal(raw, &wire); err != nil {
			return nil, err
		}
		composition, err := conversion.CompositionFromWire(wire)
		if err != nil {
			return nil, err
		}
		composition.Resolved = []planning.CatalogProfile{{Ref: planning.ProfileRef{Catalog: "namespace", Name: manualArgumentsProfile, Version: "v1"}, SourceClusterID: id, SourceNamespaceUID: "namespace", SourceUID: "synthetic-profile", Document: doc, Enabled: true}}
		return planningapp.CompileOngoingPolicyRecorders(*composition, installedArgumentsCompiler{})
	}
	spec := installedPolicyArgumentsSpec(id, "payments", "api")
	raw, _ := json.Marshal(spec)
	compiled, err := captureapp.CompilePolicyWithRecorders(t.Context(), targets.Request{}, raw, planningapp.ContextRecipeName, planningapp.RecipeDigest(), compile)
	if err != nil || compiled.Recorder == nil || !compiled.Recorder.Valid() {
		t.Fatal("installed authored policy", err)
	}
	r := compiled.Recorder
	want, err := (installedArgumentsCompiler{}).CompileArguments([]string{"write"}, true, 128)
	if err != nil || r.Arguments == nil || *r.Arguments != want || r.Action.Kind != "syscallTrace" || r.Action.ExecutionMode != "onTrigger" || r.Action.Before != "0s" || r.Action.After != "5s" || r.Action.MaxBytes != artifact.RecordingNativeLimit {
		t.Fatal("exact finite argument policy", r, err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	for op, input := range map[string]any{"request_policy_grant": installedPolicyArgumentsGrantInput(id), "request_raw_access": installedPolicyArgumentsRawInput(id, strings.Repeat("a", 64), 4096), "decide_review": installedPolicyRecordingDecisionArguments(id)} {
		raw, _ := json.Marshal(input)
		if err = wire.ValidateInput(op, raw); err != nil {
			t.Fatal(op, err)
		}
	}
}

func TestInstalledPolicyArgumentsProtectedInputSchemas(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	binding := installedPolicyArgumentsBinding(map[string]any{"subjects": []any{map[string]any{"kind": "Group", "issuer": "https://id.example.test", "id": "fixture-team"}}, "scope": map[string]any{"clusterID": id, "namespaceRef": map[string]any{"name": "payments", "uid": "namespace"}, "workloads": []any{map[string]any{"kind": "Deployment", "name": "api", "uid": "workload"}}}})
	validateInstalledPolicyProtectedInputs(t, installedPolicyArgumentsSpec(id, "payments", "api"), binding)
}

func validateInstalledPolicyProtectedInputs(t *testing.T, authored, binding map[string]any) {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	files, err := filepath.Glob("../../internal/adapters/kubernetes/policy-schemas/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		var doc map[string]any
		if err != nil || json.Unmarshal(raw, &doc) != nil {
			t.Fatal(file, err)
		}
		if err = compiler.AddResource(doc["$id"].(string), doc); err != nil {
			t.Fatal(err)
		}
	}
	schema, err := compiler.Compile("https://asservat.io/spec/v1/policy.schema.json#/properties/spec")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(authored)
	var spec any
	_ = json.Unmarshal(raw, &spec)
	if err = schema.Validate(spec); err != nil {
		t.Fatal("closed policy schema", err)
	}
	for _, item := range []struct {
		file     string
		document map[string]any
	}{
		{"debugpolicies.yaml", map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "DebugPolicy", "metadata": map[string]any{"name": installedPolicyArgumentsName}, "spec": spec}},
		{"accessbindings.yaml", binding},
	} {
		raw, err := os.ReadFile("../../charts/asservat/crds/" + item.file)
		var crd map[string]any
		if err != nil || json.Unmarshal(raw, &crd) != nil {
			t.Fatal(err)
		}
		version := crd["spec"].(map[string]any)["versions"].([]any)[0].(map[string]any)
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		if err = c.AddResource("urn:installed-input", version["schema"].(map[string]any)["openAPIV3Schema"]); err != nil {
			t.Fatal(err)
		}
		schema, err := c.Compile("urn:installed-input")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ = json.Marshal(item.document)
		var doc any
		_ = json.Unmarshal(raw, &doc)
		if err = schema.Validate(doc); err != nil {
			t.Fatal(item.file, err)
		}
	}
}
