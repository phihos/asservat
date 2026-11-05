package planning

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
)

func finiteLogsComposition(edits ...value.ProfileEdit) value.ProfileComposition {
	c := network(edits...)
	c.Components[0].Profile.Name = "finite-logs"
	c.MaxTotalBytes = artifact.LogNativeLimit
	return c
}

func TestFiniteLogsUsesExactOrdinaryCompositionPipeline(t *testing.T) {
	c := finiteLogsComposition()
	actions, _, err := expand(c, nil, nil)
	if err != nil || len(actions) != 1 || actions[0].action.Kind != "logs" {
		t.Fatal("finite logs composition unsupported", err)
	}
}

func TestFiniteLogsAcceptedContextAndProtectedReview(t *testing.T) {
	in, now := contextInput(t)
	in.Target.ExecutionClass, in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = artifact.ContextAPIExecution, "", "", ""
	in.Capability.ExecutionClass = artifact.ContextAPIExecution
	in.Retention.EvidenceType = "logs"
	in.Logs = &value.LogsContext{Composition: finiteLogsComposition(text("logs", "logBefore", "1h")), TriggeredAt: now.Add(-time.Second)}
	for _, approval := range []bool{false, true} {
		in.Logs.RequireApproval = approval
		p, err := CompileContext(in, now)
		if err != nil || !VerifyContextPlan(p, now) {
			t.Fatal("accepted logs context", err)
		}
		r, err := LogsPlanForContext(p)
		if err != nil || (r.Approval != nil) != approval {
			t.Fatal("raw native class invented or dropped collection review", err, r.Approval)
		}
		l, id, err := LogsForContext(p)
		if err != nil || l.BeforeMillis != time.Hour.Milliseconds() || l.Streams != "combined" || l.ActionID != id {
			t.Fatal("accepted selection changed", err, l)
		}
		restored, err := LogsContextFor(&l)
		if err != nil || !restored.TriggeredAt.Equal(in.Logs.TriggeredAt) || restored.RequireApproval != approval {
			t.Fatal("original policy clock or protected review changed", err)
		}
		l.MaxNativeBytes--
		if _, err := LogsContextFor(&l); err == nil {
			t.Fatal("accepted composition cap no longer matched")
		}
		assessed, err := AssessRecorder(r, "00000000-0000-4000-8000-000000000099", now)
		if err != nil || len(assessed.Actions) != 1 || !assessed.Actions[0].Exposure.UnknownContent || assessed.RulesDigest == RecorderAssessmentRulesDigest() {
			t.Fatal("logs lacks specific raw-content assessment", err)
		}
	}
	for _, stream := range []string{"stdout", "stderr"} {
		if _, _, err := expand(finiteLogsComposition(text("logs", "logStream", stream)), nil, nil); err == nil {
			t.Fatal("unqualified stream attributed", stream)
		}
	}
	if _, _, err := expand(finiteLogsComposition(text("logs", "logBefore", "25h")), nil, nil); err == nil {
		t.Fatal("historical lookback exceeded explicit ceiling")
	}
	legacy, _ := contextInput(t)
	b, _ := json.Marshal(legacy)
	if bytes.Contains(b, []byte(`"Logs"`)) {
		t.Fatal("nil logs changed legacy bytes")
	}
}

func TestFiniteLogsPolicyUsesSameHistoricalAndNativeBounds(t *testing.T) {
	c := finiteLogsComposition(text("logs", "logBefore", "1h"), value.ProfileEdit{ActionID: "logs", Field: "actionMaxBytes", Number: artifact.LogNativeLimit})
	p, err := CompilePolicyRecorder(c, nil)
	if err != nil || !p.Valid() || p.Action.Kind != "logs" || p.Action.Before != "1h" || p.Action.After != "0s" || p.Action.MaxBytes != artifact.LogNativeLimit || len(p.Action.Sensitive) != 0 {
		t.Fatal("finite policy logs were treated as a recorder ring or implicit raw approval", err, p.Action)
	}
	bad := p
	bad.Action.Before = "25h"
	if bad.Valid() {
		t.Fatal("policy lost historical bound")
	}
	// A five-second request ceiling is not a minimum acquisition duration.
	short := finiteLogsComposition(text("logs", "actionTimeout", "1s"))
	quick, err := CompilePolicyRecorder(short, nil)
	if err != nil || !quick.Valid() {
		t.Fatal("quick finite read invented a five-second minimum", err)
	}
}

func TestFiniteLogsCustomCatalogRestoresAuthoredInputsAndCurrentProvenance(t *testing.T) {
	in, now := contextInput(t)
	in.Target.ExecutionClass, in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = artifact.ContextAPIExecution, "", "", ""
	in.Capability.ExecutionClass, in.Retention.EvidenceType = artifact.ContextAPIExecution, "logs"
	raw, err := os.ReadFile("profiles/finite-logs-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["name"] = "reviewed-logs"
	document["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)["impact"] = "sensitiveRead"
	raw, _ = json.Marshal(document)
	c := finiteLogsComposition()
	ref := value.ProfileRef{Catalog: "namespace", Name: "reviewed-logs", Version: "v1"}
	c.Components[0].Profile = ref
	c.Resolved = []value.CatalogProfile{{Ref: ref, SourceClusterID: in.Target.Request.ClusterID, SourceNamespaceUID: in.Target.Request.Namespace.UID, SourceUID: "original-log-profile", Enabled: true, Document: raw}}
	in.Logs = &value.LogsContext{Composition: c, TriggeredAt: now.Add(-time.Second)}
	p, err := CompileContext(in, now)
	if err != nil {
		t.Fatal(err)
	}
	l, _, err := LogsForContext(p)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := LogsContextFor(&l)
	if err != nil || len(restored.Composition.Resolved) != 0 || !restored.TriggeredAt.Equal(in.Logs.TriggeredAt) {
		t.Fatal("authored custom logs did not restore", err)
	}
	// Restoration is not catalog authority: only a current exact catalog read
	// allows recompilation; accepted native bytes never contain its document.
	in.Logs = restored
	if _, err := CompileContext(in, now); err == nil {
		t.Fatal("missing current catalog accepted")
	}
	in.Logs.Composition.Resolved = c.Resolved
	again, err := CompileContext(in, now)
	if err != nil || again.ScopeDigest != p.ScopeDigest {
		t.Fatal("current exact catalog changed original scope", err)
	}
	parent, err := CompilePolicyRecorder(c, nil)
	child, childErr := LogsPlanForContext(p)
	if err != nil || childErr != nil || parent.Profile != child.Profiles[0] || parent.Profile.SourceUID != "original-log-profile" {
		t.Fatal("policy lost namespace profile source", err, childErr)
	}
}
