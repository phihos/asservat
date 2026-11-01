//go:build cgo && libpcap

package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/pcap"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// Real maintained dead-handle libpcap + policy/recorder compilers; no collector,
// fabricated canonical scope or installation require-all approval toggle.
func compiledRecordingReplayRow(t *testing.T, raw bool) custodydb.ContextCapture {
	t.Helper()
	p := previewTestValue(t)
	expression := "tcp dst port 80"
	if raw {
		expression = "tcp[13] & 16 != 0"
	}
	text := func(field, s string) value.ProfileEdit {
		return value.ProfileEdit{ActionID: "sample", Field: field, Text: s}
	}
	composition := value.ProfileComposition{Components: []value.ProfileComponent{{ID: "net", Profile: value.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}, Edits: []value.ProfileEdit{text("packetFilter", expression), text("actionExecutionMode", "onTrigger"), text("packetBefore", "0s"), text("packetAfter", "2s"), text("actionTimeout", "10s")}}}, MaxTotalBytes: 16 << 20, MaxDuration: "10s"}
	compiler := pcap.NewCompiler()
	if _, err := planning.CompilePolicyRecorder(composition, compiler); err != nil {
		t.Fatal("policy compile", err)
	}
	target := targets.PodResolution{Request: p.Target, Pin: p.Pin, ExecutionClass: artifact.ContextAPIExecution, PodResourceVersion: "10", WorkloadResourceVersion: "20", ObservedAt: p.CreatedAt, FreshUntil: p.CreatedAt.Add(5 * time.Second)}
	target.Pin.NodeName = ""
	retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "set", Generation: 1, Digest: [32]byte{7}}, ObservedAt: p.CreatedAt, FreshUntil: p.CreatedAt.Add(30 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{4}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", AnchorAt: p.CreatedAt}, p.CreatedAt)
	if err != nil {
		t.Fatal("retention", err)
	}
	plan, err := planning.CompileRecorder(value.RecorderInput{CaptureID: p.CaptureID, Executor: authorization.PolicyPrincipal(p.InstallationID, "raw-policy"), Target: target, Composition: composition, Retention: retention, Deadline: p.Deadline, NodeRecorder: true, RequireApproval: false}, compiler, p.CreatedAt)
	if err != nil {
		t.Fatal("recorder compile", err)
	}
	recording, action, err := planning.RecordingFor(plan)
	if err != nil || recording.RequireApproval || (plan.Approval != nil) != raw {
		t.Fatal("independent raw approval", recording.RequireApproval, err)
	}
	row := progressFactsFixture(t, "pending").ContextCapture
	var e artifact.ContextExpectation
	if err = json.Unmarshal(row.ExpectationJson, &e); err != nil {
		t.Fatal(err)
	}
	e.ExecutionClass = artifact.ContextAPIExecution
	e.NativeType = artifact.PCAPNGArtifact
	e.NodeUID, e.NodeBootID = "", ""
	e.Registration.NativeLimit = artifact.RecordingNativeLimit
	e.Recording = &recording
	e.ActionID, e.RecipeDigest, e.PlanDigest = action, plan.RecipeDigest, plan.ScopeDigest
	if err = e.Validate(); err != nil {
		t.Fatal("expectation", err)
	}
	row.ExpectationJson, _ = json.Marshal(e)
	row.PodPinJson, _ = json.Marshal(target.Pin)
	row.ScopeJson = bytes.Clone(plan.CanonicalScope)
	row.ScopeDigest = bytes.Clone(plan.ScopeDigest[:])
	return row
}

func TestRawPolicyApprovedTimingReplayIgnoresRequireAllSwitch(t *testing.T) {
	row := compiledRecordingReplayRow(t, true)
	got, err := requestRecordScope(row)
	expected := authorization.PolicyPrincipal(previewTestValue(t).InstallationID, "raw-policy")
	if err != nil || !got.ApprovedAcceptance || !got.Deadline.IsZero() || got.Actor != expected {
		t.Fatal("valid compiled raw policy replay rejected", got, err)
	}
	var e artifact.ContextExpectation
	_ = json.Unmarshal(row.ExpectationJson, &e)
	if e.Recording.RequireApproval {
		t.Fatal("replay rewrote installation setting")
	}
	for _, name := range []string{"scope-digest", "capture", "target", "malformed", "missing-approval", "unapproved-timing", "wrong-version"} {
		t.Run(name, func(t *testing.T) {
			r := row
			r.ScopeJson = bytes.Clone(row.ScopeJson)
			r.ScopeDigest = bytes.Clone(row.ScopeDigest)
			switch name {
			case "scope-digest":
				r.ScopeDigest[0] ^= 1
			case "capture":
				r.ID = r.AttemptID
			case "target":
				changed := e
				changed.WorkloadUID = "other-workload"
				r.ExpectationJson, _ = json.Marshal(changed)
			case "malformed":
				r.ScopeJson = []byte(`{`)
			default:
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(r.ScopeJson, &fields)
				switch name {
				case "missing-approval":
					delete(fields, "approval")
				case "unapproved-timing":
					delete(fields, "timing")
				case "wrong-version":
					fields["schemaVersion"] = json.RawMessage(`"unsupported/v1"`)
				}
				b, _ := json.Marshal(fields)
				canonical := jsontext.Value(b)
				if err := canonical.Canonicalize(); err != nil {
					t.Fatal(err)
				}
				r.ScopeJson = canonical
				d := sha256.Sum256(r.ScopeJson)
				r.ScopeDigest = d[:]
				changed := e
				changed.PlanDigest = d
				r.ExpectationJson, _ = json.Marshal(changed)
			}
			if _, err := requestRecordScope(r); err == nil {
				t.Fatal("mismatched historical shape accepted")
			}
		})
	}
	// A genuinely unapproved ordinary scope retains its exact absolute deadline.
	ordinary := compiledRecordingReplayRow(t, false)
	if scope, err := requestRecordScope(ordinary); err != nil || scope.ApprovedAcceptance || !scope.Deadline.Equal(ordinary.Deadline.Time) {
		t.Fatal("ordinary absolute timing", err)
	}
	ordinary.Deadline = ts(ordinary.Deadline.Time.Add(time.Second))
	if _, err := requestRecordScope(ordinary); err == nil {
		t.Fatal("ordinary deadline changed")
	}
}
