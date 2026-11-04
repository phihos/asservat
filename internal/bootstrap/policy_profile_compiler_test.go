package bootstrap

import (
	"context"
	"encoding/json"
	"testing"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	planner "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/targets"
)

type policyProfileDefinitionFixture struct {
	entries []planner.ProfileEndpointEntry
	queries int
	request targets.ProfileEndpointDefinitionRequest
	after   func(*targets.ProfileEndpointDefinitionResolution)
}

func (*policyProfileDefinitionFixture) ResolveProfileEndpoint(context.Context, targets.ProfileEndpointRequest) (targets.ProfileEndpointResolution, error) {
	panic("policy compiler resolved a Pod")
}
func (f *policyProfileDefinitionFixture) ResolveProfileEndpointDefinition(ctx context.Context, r targets.ProfileEndpointDefinitionRequest) (targets.ProfileEndpointDefinitionResolution, error) {
	f.queries++
	f.request = r
	if ctx.Err() != nil {
		return targets.ProfileEndpointDefinitionResolution{}, ctx.Err()
	}
	a, err := planner.ResolveProfileEndpointDefinition(f.entries, r)
	if f.after != nil {
		f.after(&a)
	}
	return a, err
}

func TestPolicyProfileCompilerUsesProtectedDefinitionWithoutPodOrTime(t *testing.T) {
	scope := targets.Request{ClusterID: "00000000-0000-4000-8000-000000000001", Namespace: configuration.NamespaceRef{Name: "payments", UID: "00000000-0000-4000-8000-000000000002"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}}
	raw := json.RawMessage(`{"components":[{"id":"cpu","profileRef":{"catalog":"builtin","name":"go-cpu","version":"v1"}}],"maxTotalBytes":16777216,"maxDuration":"30s"}`)
	for _, mode := range []string{"valid", "changed-definition", "wrong-request", "tampered-definition", "cancelled", "no-reader"} {
		t.Run(mode, func(t *testing.T) {
			entries, err := kube.ProfileEndpointEntries(scope.ClusterID, []contracts.RegionalProfileEndpoint{{Name: "go-pprof-loopback", Kind: "template", Namespaces: []string{"payments"}, AddressModes: []string{"targetLoopback"}, LoopbackFamily: "ipv4", MinPort: 6000, MaxPort: 6999}})
			if err != nil {
				t.Fatal(err)
			}
			f := &policyProfileDefinitionFixture{entries: entries}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "wrong-request":
				f.after = func(a *targets.ProfileEndpointDefinitionResolution) { a.Request.Namespace.UID = "replacement" }
			case "tampered-definition":
				f.after = func(a *targets.ProfileEndpointDefinitionResolution) { a.Host = "changed.invalid" }
			case "cancelled":
				f.after = func(*targets.ProfileEndpointDefinitionResolution) { cancel() }
			}
			compiler := publicPolicyRecorderCompiler(nil, nil, f)
			if mode == "no-reader" {
				compiler = publicPolicyRecorderCompiler(nil, nil)
			}
			all, err := compiler(ctx, scope, raw)
			if mode != "valid" && mode != "changed-definition" {
				if err == nil || len(all) != 0 {
					t.Fatal("unverified definition compiled", mode)
				}
				return
			}
			if err != nil || len(all) != 1 || !all[0].Valid() || f.queries != 1 || f.request.ClusterID != scope.ClusterID || f.request.Namespace != scope.Namespace {
				t.Fatal("protected compiler boundary", err, f.queries)
			}
			first := all[0]
			if first.ProfileEndpoint == nil || first.ProfileEndpoint.Definition.ScopeNamespaceUID != scope.Namespace.UID || first.Action.EndpointDigest != "" {
				t.Fatal("lost stable scope")
			}
			if mode == "changed-definition" {
				f.entries[0].Definition.Host = "new.invalid"
				f.entries[0].Definition.Source.Digest[0]++
				next, err := compiler(ctx, scope, raw)
				if err != nil || next[0].Digest == first.Digest || next[0].ProfileEndpoint.DefinitionDigest == first.ProfileEndpoint.DefinitionDigest {
					t.Fatal("changed protected definition retained acceptance", err)
				}
			}
		})
	}
}
