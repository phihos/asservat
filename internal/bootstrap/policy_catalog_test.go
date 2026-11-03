package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	planningapp "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/configuration"
	planning "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type policyCatalogFixture struct {
	target   targets.Request
	profiles []planning.CatalogProfile
	reads    int
	after    func()
}

func (f *policyCatalogFixture) ReadCatalogProfiles(ctx context.Context, target targets.PodResolution, refs []planning.ProfileRef) ([]planning.CatalogProfile, error) {
	f.reads++
	if ctx.Err() != nil || target.Request != f.target || len(refs) != 1 {
		return nil, targets.ErrChanged
	}
	if f.after != nil {
		f.after()
	}
	return f.profiles, nil
}
func (*policyCatalogFixture) ListCatalogProfiles(context.Context, targets.PodResolution, string) ([]planning.CatalogProfile, error) {
	panic("policy compiler listed catalog")
}

func policyArgumentCatalogFixture(t *testing.T, catalog string) (*policyCatalogFixture, json.RawMessage) {
	t.Helper()
	raw, err := os.ReadFile("../application/planning/profiles/syscall-activity-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["name"] = "argument-capture"
	recipe := doc["definition"].(map[string]any)["recipe"].(map[string]any)
	a := recipe["actions"].([]any)[0].(map[string]any)
	a["impact"], a["executionMode"] = "sensitiveRead", "onTrigger"
	p := a["parameters"].(map[string]any)
	p["mode"], p["before"], p["after"] = "arguments", "0s", "3s"
	p["syscalls"] = map[string]any{"mode": "include", "names": []string{"openat"}}
	p["arguments"] = map[string]any{"maxBytesPerEvent": 128, "captureBuffers": false}
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	target := targets.Request{ClusterID: "00000000-0000-4000-8000-000000000001", Namespace: configuration.NamespaceRef{Name: "payments", UID: "namespace-uid"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload-uid"}}
	ref := planning.ProfileRef{Catalog: catalog, Name: "argument-capture", Version: "v1"}
	profile := planning.CatalogProfile{Ref: ref, SourceClusterID: target.ClusterID, SourceNamespaceUID: target.Namespace.UID, SourceUID: "profile-uid", Document: raw, Enabled: true}
	if catalog == "organization" {
		profile.SourceClusterID = "00000000-0000-4000-8000-000000000002"
		profile.SourceNamespaceUID = "protected-hub-namespace"
	}
	f := &policyCatalogFixture{target: target, profiles: []planning.CatalogProfile{profile}}
	composition, _ := json.Marshal(map[string]any{"components": []any{map[string]any{"id": "calls", "profileRef": map[string]any{"catalog": catalog, "name": ref.Name, "version": ref.Version}}}, "maxTotalBytes": 16 << 20, "maxDuration": "30s"})
	return f, composition
}

func TestPolicyCatalogCompilerUsesCurrentProtectedDefinitionsAndPreservesArgumentPins(t *testing.T) {
	for _, catalog := range []string{"namespace", "organization"} {
		t.Run(catalog, func(t *testing.T) {
			f, raw := policyArgumentCatalogFixture(t, catalog)
			compile := publicPolicyRecorderCompiler(newPublicRecorderCompiler(), f)
			all, err := compile(t.Context(), f.target, raw)
			if err != nil || len(all) != 1 || !all[0].Valid() || all[0].Arguments == nil || f.reads != 1 {
				t.Fatal("published argument policy unavailable", err)
			}
			accepted := all[0]
			if accepted.Arguments.CaptureBuffers || accepted.Arguments.MaxBytesPerEvent != 128 || accepted.Composition.Resolved[0].SourceUID != "profile-uid" {
				t.Fatal("resolved mechanism/provenance lost")
			}
			// Persistent config retains the actual tuple; transient catalog documents
			// are deliberately resolved again rather than embedded as authority.
			stored, _ := json.Marshal(accepted)
			var restored planning.PolicyRecorderConfiguration
			if json.Unmarshal(stored, &restored) != nil || !restored.Valid() || !reflect.DeepEqual(restored.Arguments, accepted.Arguments) || len(restored.Composition.Resolved) != 0 {
				t.Fatal("serialized policy dropped argument pins")
			}
			exact, err := planningapp.CompilePolicyRecorder(accepted.Composition, newPublicRecorderCompiler())
			if err != nil || exact.Digest != accepted.Digest {
				t.Fatal("public compiler changed definition", err)
			}
			f.profiles[0].Enabled = false
			if _, err = compile(t.Context(), f.target, raw); err == nil {
				t.Fatal("disabled profile accepted")
			}
			f.profiles = nil
			if _, err = compile(t.Context(), f.target, raw); err == nil {
				t.Fatal("deleted profile accepted")
			}
		})
	}
}

func TestPolicyCatalogCompilerPreservesOriginalCancellationAndExactScope(t *testing.T) {
	for _, mode := range []string{"unbound", "wrong-namespace", "caller-pod", "cancelled", "cancel-after-read"} {
		t.Run(mode, func(t *testing.T) {
			f, raw := policyArgumentCatalogFixture(t, "namespace")
			scope := f.target
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "unbound":
				scope = targets.Request{}
			case "wrong-namespace":
				scope.Namespace.UID = "replacement"
			case "caller-pod":
				scope.PodUID = "invented"
			case "cancelled":
				cancel()
			case "cancel-after-read":
				f.after = cancel
			}
			_, err := publicPolicyRecorderCompiler(newPublicRecorderCompiler(), f)(ctx, scope, raw)
			if err == nil {
				t.Fatal("changed/cancelled catalog scope accepted")
			}
			if mode == "cancel-after-read" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if (mode == "unbound" || mode == "caller-pod" || mode == "cancelled") && f.reads != 0 {
				t.Fatal("invalid scope read catalog")
			}
		})
	}
	// Builtins add no catalog request.
	f, _ := policyArgumentCatalogFixture(t, "namespace")
	if _, err := publicPolicyRecorderCompiler(ongoingCompilerFilters{}, f)(t.Context(), f.target, ongoingCompilerComposition(t, "ongoing", "0s")); err != nil || f.reads != 0 {
		t.Fatal("builtin performed catalog read", err)
	}
}
