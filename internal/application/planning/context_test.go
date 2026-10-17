package planning

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

func contextInput(t *testing.T) (value.ContextInput, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	target := targets.PodResolution{Request: targets.Request{ClusterID: "00000000-0000-4000-8000-000000000001", Namespace: configuration.NamespaceRef{Name: "payments", UID: "namespace-payments-uid"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "deployment-api-uid"}, PodName: "api-123", PodUID: "pod-uid"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "namespace-payments-uid", Name: "api-123", UID: "pod-uid", NodeName: "worker", ControllerUID: "replicaset-uid"}, NodeUID: "node-uid", NodeBootID: "00000000-0000-4000-8000-000000000006", PodResourceVersion: "10", WorkloadResourceVersion: "20", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	set := privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "policy-set", Generation: 1, Digest: [32]byte{7}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{4}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}
	r, err := privacy.Resolve(set, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "context", AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	return value.ContextInput{CaptureID: "00000000-0000-4000-8000-000000000045", Executor: identity.Principal{Issuer: "https://identity.example.invalid/realms/company", Subject: "developer-123", ClientID: "asservat-browser", Kind: identity.Human}, Deadline: now.Add(time.Minute), Target: target, Retention: r, Capability: value.ContextCapability{Revision: identity.Revision{UID: "context-capability", Generation: 1, Digest: [32]byte{2}}, Enabled: true, CollectorVersion: "synthetic-1", CollectorImageDigest: artifact.Digest{3}, ProjectionDigest: ProjectionDigest(), ObservedAt: now, FreshUntil: now.Add(30 * time.Second)}}, now
}

func TestContextScopeCrossLanguageFixture(t *testing.T) {
	in, now := contextInput(t)
	p, err := CompileContext(in, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../../examples/resolved-context-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	want, _, err := canonical(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.CanonicalScope, want) {
		t.Fatalf("compiled scope differs from independently checked fixture:\n%s", p.CanonicalScope)
	}
	if !VerifyContextPlan(p, now) || !p.ValidUntil.Equal(in.Target.FreshUntil) {
		t.Fatal("compiled plan cannot be verified")
	}
	in.Retention.Policies[0].UID = "replacement"
	if !VerifyContextPlan(p, now) {
		t.Fatal("caller mutated frozen plan")
	}
	p.CanonicalScope[1] = '!'
	if VerifyContextPlan(p, now) {
		t.Fatal("altered canonical scope accepted")
	}
}

func TestAPIContextScopeRequiresExplicitQualifiedClass(t *testing.T) {
	in, now := contextInput(t)
	node, err := CompileContext(in, now)
	if err != nil {
		t.Fatal(err)
	}
	in.Target.ExecutionClass = artifact.ContextAPIExecution
	in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = "", "", ""
	if _, err := CompileContext(in, now); err == nil {
		t.Fatal("API target accepted using node capability")
	}
	in.Capability.ExecutionClass = artifact.ContextAPIExecution
	api, err := CompileContext(in, now)
	if err != nil || !VerifyContextPlan(api, now) || api.ScopeDigest == node.ScopeDigest {
		t.Fatal("explicit API plan not bound independently", err)
	}
	if !bytes.Contains(api.CanonicalScope, []byte(`"executionClass":"kubernetesAPI"`)) || bytes.Contains(api.CanonicalScope, []byte(`"nodeUID"`)) || bytes.Contains(api.CanonicalScope, []byte(`"nodeBootID"`)) {
		t.Fatal("API plan invents node authority or omits class")
	}
	for name, change := range map[string]func(*value.ContextInput){
		"node UID":       func(i *value.ContextInput) { i.Target.NodeUID = "node" },
		"boot ID":        func(i *value.ContextInput) { i.Target.NodeBootID = "00000000-0000-4000-8000-000000000006" },
		"node pin":       func(i *value.ContextInput) { i.Target.Pin.NodeName = "node" },
		"implicit class": func(i *value.ContextInput) { i.Target.ExecutionClass = artifact.ContextNodeExecution },
		"unknown class":  func(i *value.ContextInput) { i.Target.ExecutionClass = "unqualified" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := in
			change(&bad)
			if _, err := CompileContext(bad, now); err == nil {
				t.Fatal("mixed or implicit class accepted")
			}
		})
	}
}

func TestContextScopeBindsConsequentialChanges(t *testing.T) {
	tests := []struct {
		name   string
		change func(*value.ContextInput)
	}{
		{"capture", func(i *value.ContextInput) { i.CaptureID = "00000000-0000-4000-8000-000000000046" }},
		{"deadline", func(i *value.ContextInput) { i.Deadline = i.Deadline.Add(time.Second) }},
		{"actor", func(i *value.ContextInput) { i.Executor.Subject = "another-developer" }},
		{"client", func(i *value.ContextInput) { i.Executor.ClientID = "mcp-client" }},
		{"boot", func(i *value.ContextInput) { i.Target.NodeBootID = "00000000-0000-4000-8000-000000000007" }},
		{"node", func(i *value.ContextInput) { i.Target.NodeUID = "other-node" }},
		{"ceiling", func(i *value.ContextInput) { i.Capability.Revision.Digest[0]++ }},
		{"collector", func(i *value.ContextInput) { i.Capability.CollectorImageDigest[0]++ }},
		{"policy-identity", func(i *value.ContextInput) { i.Retention.Policies[0].UID = "replacement" }},
		{"policy-generation", func(i *value.ContextInput) { i.Retention.Policies[0].Generation++ }},
		{"maximum", func(i *value.ContextInput) { i.Retention.MaximumSeconds = 7200 }},
		{"request", func(i *value.ContextInput) {
			i.Retention.RequestedSeconds = 1800
			i.Retention.ExpiresAt = i.Retention.AnchorAt.Add(1800 * time.Second)
			i.Retention.DeleteBy = i.Retention.ExpiresAt.Add(300 * time.Second)
		}},
		{"budget", func(i *value.ContextInput) {
			i.Retention.DeletionBudgetSeconds = 600
			i.Retention.DeleteBy = i.Retention.ExpiresAt.Add(600 * time.Second)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			in, now := contextInput(t)
			old, err := CompileContext(in, now)
			if err != nil {
				t.Fatal(err)
			}
			test.change(&in)
			next, err := CompileContext(in, now)
			if err != nil {
				t.Fatal(err)
			}
			if old.ScopeDigest == next.ScopeDigest {
				t.Fatal("material change preserved approval digest")
			}
		})
	}
	// Resource-version refresh and later freshness checks do not renew the
	// capture identity or change its immutable execution scope.
	in, now := contextInput(t)
	old, _ := CompileContext(in, now)
	in.Target.PodResourceVersion = "11"
	in.Target.ObservedAt = now.Add(time.Second)
	in.Target.FreshUntil = now.Add(6 * time.Second)
	next, err := CompileContext(in, now.Add(time.Second))
	if err != nil || next.ScopeDigest != old.ScopeDigest {
		t.Fatal("freshness became approval identity", err)
	}
}

func TestContextScopeRejectsUnsafeInputs(t *testing.T) {
	tests := []struct {
		name   string
		change func(*value.ContextInput)
	}{
		{"unqualified", func(i *value.ContextInput) { i.Capability.Enabled = false }},
		{"unknown-projection", func(i *value.ContextInput) { i.Capability.ProjectionDigest[0]++ }},
		{"expired-target", func(i *value.ContextInput) { i.Target.FreshUntil = i.Target.ObservedAt }},
		{"substituted-target", func(i *value.ContextInput) { i.Target.Request.PodUID = "other" }},
		{"retention-target", func(i *value.ContextInput) { i.Retention.Target.WorkloadUID = "other" }},
		{"widened-deadline", func(i *value.ContextInput) { i.Deadline = i.Deadline.Add(time.Hour) }},
		{"no-policy", func(i *value.ContextInput) { i.Retention.Policies = nil }},
		{"forged-class", func(i *value.ContextInput) { i.Retention.PrivacyClass = "verifiedNonPersonal" }},
		{"forged-type", func(i *value.ContextInput) { i.Retention.EvidenceType = "coreDump" }},
		{"budget-outside-cap", func(i *value.ContextInput) { i.Retention.DeletionBudgetSeconds = i.Retention.MaximumSeconds }},
		{"extended-expiry", func(i *value.ContextInput) { i.Retention.ExpiresAt = i.Retention.ExpiresAt.Add(time.Hour) }},
		{"late-deletion", func(i *value.ContextInput) { i.Retention.DeleteBy = i.Retention.DeleteBy.Add(time.Hour) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			in, now := contextInput(t)
			test.change(&in)
			if _, err := CompileContext(in, now); err == nil {
				t.Fatal("unsafe plan accepted")
			}
		})
	}
}

func TestRecipeHasOnlyQualifiedAction(t *testing.T) {
	var recipe struct {
		Actions []struct {
			Kind          string
			Parameters    map[string][]string
			ExecutionMode string
		}
	}
	if json.Unmarshal([]byte(ContextRecipeSpec), &recipe) != nil || len(recipe.Actions) != 1 || recipe.Actions[0].Kind != "kubernetesSnapshot" || recipe.Actions[0].ExecutionMode != "onTrigger" || len(recipe.Actions[0].Parameters["include"]) != 1 || recipe.Actions[0].Parameters["include"][0] != "pod" {
		t.Fatal("recipe drift")
	}
}

func TestRetentionRuntimeFenceDoesNotChangeApprovalIdentity(t *testing.T) {
	in, now := contextInput(t)
	original, err := CompileContext(in, now)
	if err != nil {
		t.Fatal(err)
	}
	root := "11111111-1111-4111-8111-111111111111"
	rev := identity.Revision{UID: root, Generation: 1, Digest: artifact.Digest{1}}
	target := in.Target.Target()
	in.Retention.ValidUntil = now.Add(5 * time.Second)
	in.Retention.Proof = artifact.RetentionProof{RootID: root, ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, PodUID: target.PodUID, Topology: rev, Policy: in.Retention.PolicyRevision, Selectors: rev, SourceCount: 1, ObservedAt: now, ValidUntil: in.Retention.ValidUntil, Sources: [2]artifact.RetentionSourceVersion{{ClusterID: target.ClusterID, ControlNamespaceUID: "control", Epoch: root, Hub: true, ProtectionDigest: artifact.Digest{2}, SnapshotDigest: artifact.Digest{3}, Acceptance: rev}}}
	for _, epoch := range []string{root, "22222222-2222-4222-8222-222222222222"} {
		in.Retention.Proof.Sources[0].Epoch = epoch
		p, err := CompileContext(in, now)
		if err != nil || p.ScopeDigest != original.ScopeDigest {
			t.Fatal("runtime source epoch changed approval scope", err)
		}
	}
	for _, edit := range []func(*value.ContextInput){
		func(i *value.ContextInput) { i.Retention.Proof.PodUID = "replacement" },
		func(i *value.ContextInput) { i.Retention.Proof.Policy.Digest[0]++ },
		func(i *value.ContextInput) { i.Retention.ValidUntil = i.Retention.ValidUntil.Add(time.Second) },
	} {
		bad := in
		edit(&bad)
		if _, err := CompileContext(bad, now); err == nil {
			t.Fatal("invalid proof binding")
		}
	}
}
