package integration

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/presentation"
)

func installedRecordingFocus() bool {
	return installedJourneyFocus() == "approved-recording" || installedJourneyFocus() == "native-paced" || installedJourneyFocus() == "policy-recording"
}

// This is a separate reviewed public capture request, before independent
// approval. It does not lengthen the accepted PR-100 recording or its deadlines.
func nativePacingArguments(cluster, namespace, workload string) map[string]any {
	input := approvedRecordingArguments(cluster, namespace, workload)
	composition := input["profile_composition"].(map[string]any)
	component := composition["components"].([]any)[0].(map[string]any)
	component["overrides"] = []any{
		map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"},
		map[string]any{"actionID": "sample", "field": "packetAfter", "value": "10s"},
		map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "20s"},
	}
	composition["maxDuration"] = "20s"
	return input
}

func TestNativePacingReviewedCaptureInput(t *testing.T) {
	const cluster = "00000000-0000-4000-8000-000000000001"
	ordinary, err := json.Marshal(approvedRecordingArguments(cluster, "payments", "api"))
	if err != nil {
		t.Fatal(err)
	}
	input := nativePacingArguments(cluster, "payments", "api")
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.ValidateInput("preview_capture", raw); err != nil {
		t.Fatal("reviewed finite pacing request is not a public capture input", err)
	}
	composition := input["profile_composition"].(map[string]any)
	if composition["maxTotalBytes"] != 16<<20 || composition["maxDuration"] != "20s" {
		t.Fatal("qualification changed aggregate byte ceiling or lost finite duration")
	}
	// Schema validity does not establish that this immutable builtin exposes
	// every requested edit. Exercise the real planner with synthetic facts and
	// the existing test filter compiler; no capture or kernel work is performed.
	compositionJSON, err := json.Marshal(composition)
	if err != nil {
		t.Fatal(err)
	}
	var public presentation.CompositionInput
	if err := json.Unmarshal(compositionJSON, &public); err != nil {
		t.Fatal(err)
	}
	resolved := planvalue.ProfileComposition{MaxTotalBytes: public.MaxTotalBytes, MaxDuration: public.MaxDuration}
	for _, c := range public.Components {
		component := planvalue.ProfileComponent{ID: c.ID, Profile: planvalue.ProfileRef{Catalog: c.ProfileRef.Catalog, Name: c.ProfileRef.Name, Version: c.ProfileRef.Version}}
		for _, o := range c.Overrides {
			edit := planvalue.ProfileEdit{ActionID: o.ActionID, Field: o.Field}
			if o.Field == "actionMaxBytes" {
				err = json.Unmarshal(o.Value, &edit.Number)
			} else {
				err = json.Unmarshal(o.Value, &edit.Text)
			}
			if err != nil {
				t.Fatal("pacing override", err)
			}
			component.Edits = append(component.Edits, edit)
		}
		resolved.Components = append(resolved.Components, component)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	target := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: targets.Request{ClusterID: cluster, Namespace: configuration.NamespaceRef{Name: "payments", UID: "namespace"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "namespace", Name: "api-a", UID: "pod", ControllerUID: "replicaset"}, PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "policies", Generation: 1, Digest: artifact.Digest{1}}, Complete: true, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 600, MaximumSeconds: 3600, DeletionBudgetSeconds: 10}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: 600, AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compiler.CompileRecorder(planvalue.RecorderInput{CaptureID: cluster, Executor: identity.Principal{Issuer: "https://identity.example.test", Subject: "requester", ClientID: "console", Kind: identity.Human}, Target: target, Composition: resolved, Retention: retention, Deadline: now.Add(time.Minute), NodeRecorder: true, RequireApproval: true}, recordingCompiler{}, now)
	if err != nil {
		t.Fatal("pacing request cannot compile through the actual builtin planner", err)
	}
	recording, _, err := compiler.RecordingFor(plan)
	if err != nil || recording.DurationMillis != 10000 || recording.MaxBytes != artifact.RecordingNativeLimit || !recording.RequireApproval {
		t.Fatal("pacing plan lost its reviewed duration, native cap or approval", recording, err)
	}
	after, _ := json.Marshal(approvedRecordingArguments(cluster, "payments", "api"))
	if string(after) != string(ordinary) {
		t.Fatal("pacing request changed the original approved-recording fixture")
	}
}

func TestNativePacingRangesFitExistingSessionBudget(t *testing.T) {
	typeInfo, ok := artifact.LookupNativeType(artifact.PCAPNGArtifact)
	if !ok {
		t.Fatal("PCAPNG native type missing")
	}
	// The fixed source bounds include frame/index cipher overhead even for a
	// half-file range. Preparation charges four MiB; each response 8.375MiB.
	read := evidence.ContextDownloadReadWork + 2*evidence.NativeWindowReadWork(typeInfo)
	if read != 21757952 || read > 24<<20 {
		t.Fatal("two ranges exceed the unchanged 24MiB session", read)
	}
}
