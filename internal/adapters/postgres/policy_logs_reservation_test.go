package postgres

import (
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestPolicyLogsBindsActualAcceptedActionWithoutInventedApproval(t *testing.T) {
	for _, mode := range []struct{ required, sensitive bool }{{false, false}, {true, false}, {false, true}} {
		required := mode.required
		a := compiledSensitiveAdmission(t, false, false, true)
		in := a.Plan.Input
		in.Recorder = nil
		in.Retention.EvidenceType = "logs"
		c := planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "saved", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "finite-logs", Version: "v1"}, Edits: []planvalue.ProfileEdit{{ActionID: "logs", Field: "actionMaxBytes", Number: artifact.LogNativeLimit}, {ActionID: "logs", Field: "logBefore", Text: "24h"}}}}, MaxTotalBytes: artifact.LogNativeLimit, MaxDuration: "10s"}
		if mode.sensitive {
			document, err := os.ReadFile("../../application/planning/profiles/finite-logs-v1.json")
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if json.Unmarshal(document, &doc) != nil {
				t.Fatal("logs definition")
			}
			doc["name"] = "reviewed-logs"
			doc["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)["impact"] = "sensitiveRead"
			document, _ = json.Marshal(doc)
			ref := planvalue.ProfileRef{Catalog: "namespace", Name: "reviewed-logs", Version: "v1"}
			c.Components[0].Profile = ref
			c.Resolved = []planvalue.CatalogProfile{{Ref: ref, SourceClusterID: in.Target.Request.ClusterID, SourceNamespaceUID: in.Target.Request.Namespace.UID, SourceUID: "reviewed-logs-source", Document: document, Enabled: true}}
		}
		parent, err := planning.CompilePolicyRecorder(c, nil)
		if err != nil {
			t.Fatal("actual logs parent compiler", err)
		}
		in.Logs = &planvalue.LogsContext{Composition: c, RequireApproval: required, TriggeredAt: a.Plan.CompiledAt}
		child, err := planning.CompileContext(in, a.Plan.CompiledAt)
		if err != nil {
			t.Fatal(err)
		}
		row := policyGrantTestRow(t)
		g, err := grantFromRow(row)
		if err != nil {
			t.Fatal(err)
		}
		authority := &g.Policy.Authority
		authority.Actions = []string{"logs"}
		authority.Limits = authorization.AutomationLimits{MaxExecutions: 4, MaxBytes: 256 << 20}
		p := previewTestValue(t)
		policy := capture.RestartPolicy{ClusterID: authority.ClusterID, Namespace: p.Target.Namespace.Name, WorkloadKind: p.Target.Workload.Kind, WorkloadName: p.Target.Workload.Name, Reasons: []string{"Error"}, Interval: time.Minute, Burst: 1, RetentionSeconds: 3600, ObservedPods: 1, Recorder: &parent}
		g.Scope = captureapp.RecorderPolicyScope(authority.PolicyUID, 1, artifact.Digest{19}, policy, authority.NamespaceUID, authority.WorkloadUID, authority.Delegation, authority.Owners, authority.Actions, authority.Limits)
		authority.ScopeDigest = sha256.Sum256(g.Scope)
		g.ExecutionDigest = authority.ScopeDigest
		g.DataClass = "raw"
		g.Policy.RecipeDigest = parent.RecipeDigest
		g.Policy.Limits = authority.Limits
		g.Reasons = []authorization.SensitiveReason{{ActionID: parent.Action.ID, Code: "policyCollection"}}
		for _, code := range parent.Action.Sensitive {
			g.Reasons = append(g.Reasons, authorization.SensitiveReason{ActionID: parent.Action.ID, Code: code})
		}
		if !authapp.PolicyLogsGrantScopeValid(g) || !policyLogsPlanMatches(g, child) {
			cp, _ := planning.LogsPlanForContext(child)
			ap, _ := authapp.PolicyLogsGrantRecorder(g)
			l, _, _ := planning.LogsForContext(child)
			lc, le := planning.LogsContextFor(&l)
			var dg bool
			if le == nil {
				again, _ := planning.CompilePolicyRecorder(lc.Composition, nil)
				dg = again.Digest == ap.Digest
			}
			t.Fatalf("exact logs parent/child require=%t sensitive=%t scope=%t acquisition=%t restored=%v digest=%t originalProfile=%t storedProfile=%t", required, mode.sensitive, authapp.PolicyLogsGrantScopeValid(g), policyLogsAcquisitionMatches(g, &l, child.RecipeDigest), le, dg, parent.Profile == cp.Profiles[0], ap.Profile == cp.Profiles[0])
		}
		if mode.sensitive {
			omitted := g
			omitted.Reasons = []authorization.SensitiveReason{{ActionID: parent.Action.ID, Code: "policyCollection"}}
			if authapp.PolicyLogsGrantScopeValid(omitted) || policyLogsPlanMatches(omitted, child) {
				t.Fatal("authored sensitive reason omitted from actual parent")
			}
		}
		l, _, err := planning.LogsForContext(child)
		if err != nil {
			t.Fatal(err)
		}
		for name, mutate := range map[string]func(*artifact.LogCapture){"before": func(l *artifact.LogCapture) { l.BeforeMillis-- }, "after": func(l *artifact.LogCapture) { l.AfterMillis++ }, "limit": func(l *artifact.LogCapture) { l.MaxNativeBytes-- }, "stream": func(l *artifact.LogCapture) { l.Streams = "stdout" }, "action": func(l *artifact.LogCapture) { l.ActionID = "a111111111111111111111111" }} {
			copy := l
			mutate(&copy)
			if policyLogsAcquisitionMatches(g, &copy, child.RecipeDigest) {
				t.Fatal("different logs action accepted", name)
			}
		}
	}
}
