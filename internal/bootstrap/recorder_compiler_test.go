package bootstrap

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/pcap"
	"asservat.local/asservat/internal/adapters/syscalls"
	planner "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

func TestPublicRecorderCompilerArgumentPlan(t *testing.T) {
	for _, names := range [][]string{{"write", "read"}, {"openat", "close"}, {"execve"}} {
		t.Run(names[0], func(t *testing.T) {
			in, now := publicArgumentPlanInput(t, names)
			plan, err := planner.CompileRecorder(in, newPublicRecorderCompiler(), now)
			if names[0] == "execve" {
				var refusal planning.CompositionError
				if !errors.As(err, &refusal) || refusal.Code != planning.CompositionRecorderUnavailable {
					t.Fatal("unsupported name was not refused by the planner", err)
				}
				return
			}
			if err != nil {
				t.Fatal("public compiler cannot compile qualified arguments", err)
			}
			recording, _, err := planner.RecordingFor(plan)
			if err != nil || recording.Arguments == nil || !planner.AcceptableRecorder(plan).Acceptable() {
				t.Fatal("qualified mechanism lost at plan acceptance", err)
			}
			defs, err := syscalls.ArgumentDefinitions(names, false, 128)
			if err != nil {
				t.Fatal(err)
			}
			a := recording.Arguments
			if hex.EncodeToString(a.ProgramDigest[:]) != gadget.ArgumentObjectSHA256 || a.DefinitionDigest != artifact.Digest(syscalls.ArgumentDefinitionDigest(defs)) || a.AccountingRule != artifact.Digest(collector.ArgumentObservationAccountingRule()) || a.MaxProbeBytes != int64(syscalls.ArgumentMaxProbeBytes(defs)) || a.MaxBytesPerEvent != 128 || a.CaptureBuffers || a.MaxBytesPerSecond != planning.SensitiveMaxBytesPerSecond {
				t.Fatal("plan differs from installed engine definitions", a)
			}
			if plan.Approval == nil || plan.Approval.DataClass != "raw" || plan.Approval.ObservationLimits == nil || !planner.ManualObservationIssued(plan.Actions, plan.Approval) {
				t.Fatal("argument compiler bypassed raw observation approval")
			}
		})
	}
}

func TestPublicRecorderCompilerPreservesPacketCompilation(t *testing.T) {
	actual, direct := newPublicRecorderCompiler(), pcap.NewCompiler()
	for _, expression := range []string{"tcp port 443", "tcp and ("} {
		got, err := actual.CompileFilter(expression)
		want, wantErr := direct.CompileFilter(expression)
		if (err == nil) != (wantErr == nil) || !reflect.DeepEqual(got, want) || err != nil && err.Error() != wantErr.Error() {
			t.Fatal("packet compiler behavior changed", expression, got, err, want, wantErr)
		}
		if expression == "tcp port 443" && direct.Version() != "" && (err != nil || len(got.Program) == 0) {
			t.Fatal("libpcap build failed to compile an ordinary packet filter", err)
		}
	}
}

func publicArgumentPlanInput(t *testing.T, names []string) (planning.RecorderInput, time.Time) {
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
	action := doc["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)
	action["impact"], action["executionMode"] = "sensitiveRead", "onTrigger"
	parameters := action["parameters"].(map[string]any)
	parameters["mode"], parameters["before"], parameters["after"] = "arguments", "0s", "3s"
	parameters["syscalls"] = map[string]any{"mode": "include", "names": names}
	parameters["arguments"] = map[string]any{"maxBytesPerEvent": 128, "captureBuffers": false}
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	target := targets.PodResolution{Request: targets.Request{ClusterID: runtimeID, Namespace: configuration.NamespaceRef{Name: "synthetic", UID: "namespace-uid"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "app", UID: "workload-uid"}, PodName: "app-123", PodUID: "pod-uid"}, Pin: artifact.PinnedPod{Namespace: "synthetic", NamespaceUID: "namespace-uid", Name: "app-123", UID: "pod-uid", NodeName: "node", ControllerUID: "replicaset-uid"}, NodeUID: "node-uid", NodeBootID: runtimeID, PodResourceVersion: "10", WorkloadResourceVersion: "20", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "policy-set", Generation: 1, Digest: artifact.Digest{1}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "syscallTrace", AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	ref := planning.ProfileRef{Catalog: "namespace", Name: "argument-capture", Version: "v1"}
	composition := planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "calls", Profile: ref}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s", Resolved: []planning.CatalogProfile{{Ref: ref, SourceClusterID: runtimeID, SourceNamespaceUID: "namespace-uid", SourceUID: "argument-profile-uid", Document: raw, Enabled: true}}}
	return planning.RecorderInput{CaptureID: runtimeID, Executor: identity.Principal{Issuer: "https://identity.synthetic.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}, Target: target, Composition: composition, Retention: retention, Deadline: now.Add(time.Minute)}, now
}
