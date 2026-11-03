package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/syscalls"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
)

func TestInstalledManualArgumentsRequestCompiles(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-arguments")
	const cluster = "00000000-0000-4000-8000-000000000001"
	for _, stop := range []bool{false, true} {
		input := manualArgumentsCaptureInput(cluster, "payments", "api", stop)
		raw, _ := json.Marshal(input)
		wire, err := contracts.NewInvestigationContracts()
		if err != nil {
			t.Fatal(err)
		}
		if err = wire.ValidateInput("preview_capture", raw); err != nil {
			t.Fatal("public argument preview", err)
		}
		compositionJSON, _ := json.Marshal(input["profile_composition"])
		var public contracts.CaptureComposition
		if err = json.Unmarshal(compositionJSON, &public); err != nil {
			t.Fatal(err)
		}
		composition, err := conversion.CompositionFromWire(public)
		if err != nil {
			t.Fatal(err)
		}
		definition, err := manualArgumentsProfileDefinition()
		if err != nil {
			t.Fatal(err)
		}
		doc, _ := json.Marshal(map[string]any{"name": manualArgumentsProfile, "version": "v1", "definition": definition})
		composition.Resolved = []planvalue.CatalogProfile{{Ref: planvalue.ProfileRef{Catalog: "namespace", Name: manualArgumentsProfile, Version: "v1"}, SourceClusterID: cluster, SourceNamespaceUID: "namespace", SourceUID: "argument-profile", Document: doc, Enabled: true}}
		now := time.Now().UTC().Truncate(time.Microsecond)
		target := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: targets.Request{ClusterID: cluster, Namespace: configuration.NamespaceRef{Name: "payments", UID: "namespace"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "namespace", Name: "api-a", UID: "pod", ControllerUID: "replicaset"}, PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "policies", Generation: 1, Digest: artifact.Digest{1}}, Complete: true, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 600, MaximumSeconds: 3600, DeletionBudgetSeconds: 10}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "syscallTrace", RequestedSeconds: 600, AnchorAt: now}, now)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := compiler.CompileRecorder(planvalue.RecorderInput{CaptureID: cluster, Executor: identity.Principal{Issuer: "https://identity.example.test", Subject: "requester", ClientID: "console", Kind: identity.Human}, Target: target, Composition: *composition, Retention: retention, Deadline: now.Add(time.Minute), NodeRecorder: true, RequireApproval: true}, installedArgumentsCompiler{}, now)
		if err != nil {
			t.Fatal("argument request compilation", stop, err)
		}
		seconds := int64(5)
		if stop {
			seconds = 30
		}
		if plan.Approval == nil || plan.Approval.DataClass != "raw" || plan.Approval.ObservationLimits == nil || plan.Approval.ObservationLimits.MaxObservedEvents != manualArgumentsRate*(seconds+1) || !compiler.AcceptableRecorder(plan).Acceptable() {
			t.Fatal("argument plan lost raw reviewed event ceiling", plan.Approval)
		}
		recording, action, err := compiler.RecordingFor(plan)
		mechanism, _ := (installedArgumentsCompiler{}).CompileArguments([]string{"write"}, !stop, 128)
		if err != nil || recording.Arguments == nil || *recording.Arguments != mechanism || recording.Arguments.CaptureBuffers == stop || recording.DurationMillis != seconds*1000 || recording.Kind != "syscallTrace" || recording.Profile != "arguments" || recording.Syscalls.MaxEventsPerSecond != manualArgumentsRate || recording.Syscalls.MaxTrackedThreads != 64 || recording.Snaplen != 0 {
			t.Fatal("accepted argument recording", recording, err)
		}
		frozen, err := compiler.RecorderContextFor(&recording)
		if err != nil {
			t.Fatal(err)
		}
		frozen.Composition.Resolved = composition.Resolved
		capability := planvalue.ContextCapability{ExecutionClass: artifact.ContextAPIExecution, Enabled: true, Revision: identity.Revision{UID: "ceiling", Generation: 1, Digest: artifact.Digest{1}}, CollectorVersion: "v1", CollectorImageDigest: artifact.Digest{2}, ProjectionDigest: compiler.ProjectionDigest(), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		if _, err = compiler.CompileContext(planvalue.ContextInput{CaptureID: cluster, Executor: identity.Principal{Issuer: "https://identity.example.test", Subject: "requester", ClientID: "console", Kind: identity.Human}, Deadline: now.Add(time.Minute), Target: target, Capability: capability, Retention: retention, Recorder: frozen}, now); err != nil {
			t.Fatal("frozen argument context recompilation", err)
		}
		var preview installedApprovedRecordingPreview
		encoded, _ := json.Marshal(map[string]any{"preview_id": cluster, "lifecycle_plan": map[string]any{"actions": []any{map[string]any{"actionID": action}}}})
		if err = json.Unmarshal(encoded, &preview); err != nil {
			t.Fatal(err)
		}
		request, resolution := manualRecorderStopRequests(preview, now, "arguments")
		for op, args := range map[string]any{"request_capture": request, "resolve_capture_request": resolution} {
			raw, _ := json.Marshal(args)
			if err = wire.ValidateInput(op, raw); err != nil {
				t.Fatal("argument Stop wire", op, err)
			}
		}
		if request["result_access"] == nil || len(resolution) != 2 {
			t.Fatal("Stop lost original raw result-access or separate resolution")
		}
	}
}

func manualArgumentsNativeFixture(t *testing.T) ([]byte, installedArgumentsSource) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	args, err := (installedArgumentsCompiler{}).CompileArguments([]string{"write"}, true, 128)
	if err != nil {
		t.Fatal(err)
	}
	source := artifact.ArgumentSourceProvenance{PodUID: "pod", NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch", SessionID: "session", Fence: "fence", StartedAt: now, StartBy: now.Add(time.Second), Until: now.Add(6 * time.Second)}
	expected := installedArgumentsSource{Source: source, Arguments: args, ByteCredit: 6 * planvalue.SensitiveMaxBytesPerSecond, EventCredit: manualArgumentsRate * 6, DurationMillis: 5000, Rate: manualArgumentsRate}
	header := artifact.ArgumentHeader{Record: "header", Format: syscalls.ArgumentNativeFormat, PodUID: source.PodUID, NodeUID: source.NodeUID, BootID: source.BootID, CollectorPodUID: source.CollectorPodUID, SourceEpoch: source.CollectorEpoch, SessionID: source.SessionID, Fence: source.Fence, EngineDigest: hex.EncodeToString(args.ProgramDigest[:]), DefinitionDigest: hex.EncodeToString(args.DefinitionDigest[:]), AccountingRule: hex.EncodeToString(args.AccountingRule[:]), Decoder: syscalls.ArgumentDecoderVersion, ABI: syscalls.ABI, StartedAt: now}
	duration, events, charged := uint64(1), uint64(2), uint64(768)
	event := artifact.ArgumentEventLine{Record: "event", Event: artifact.RawArgumentEvent{Identity: artifact.ArgumentIdentity{PodUID: "pod", ProcessRef: "p:1:1@boot@epoch", ThreadRef: "t:1:1@boot@epoch"}, Syscall: "write", ABI: syscalls.ABI, Timestamp: now.Format(time.RFC3339Nano), DurationNS: &duration, Outcome: "success", Arguments: []artifact.ArgumentValue{{Name: "fd", Value: "decimal:1"}, {Name: "buffer", Value: "base64:" + base64.StdEncoding.EncodeToString([]byte(manualArgumentsMarker+"\n"))}}}}
	footer := artifact.ArgumentFooter{Record: "footer", EndedAt: now.Add(5 * time.Second), Outcome: "completed", Retained: 1, CoverageUnknown: true, ObservedEvents: &events, ObservedBytes: &charged}
	var native []byte
	for _, line := range []any{header, event, footer} {
		native, err = syscalls.AppendArgumentLine(native, line)
		if err != nil {
			t.Fatal(err)
		}
	}
	return native, expected
}

func TestInstalledManualArgumentsNativeChecksOriginalSourceAndCounters(t *testing.T) {
	raw, source := manualArgumentsNativeFixture(t)
	if _, err := checkManualArgumentsNative(raw, "pod", source); err != nil {
		t.Fatal("valid synthetic write", err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"wrong source": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"fence":"fence"`), []byte(`"fence":"replacement"`), 1)
		},
		"no footer": func(p []byte) []byte { return p[:bytes.LastIndex(p[:len(p)-1], []byte{'\n'})+1] },
		"unknown counters": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"observed_events":2`), []byte(`"observed_events":null`), 1)
		},
		"over credit": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"observed_events":2`), []byte(`"observed_events":6001`), 1)
		},
		"wrong charge": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"observed_bytes":768`), []byte(`"observed_bytes":1`), 1)
		},
		"no actual marker": func(p []byte) []byte {
			return bytes.Replace(p, []byte(base64.StdEncoding.EncodeToString([]byte(manualArgumentsMarker+"\n"))), []byte(base64.StdEncoding.EncodeToString([]byte("unrelated"))), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := checkManualArgumentsNative(mutate(bytes.Clone(raw)), "pod", source); err == nil {
				t.Fatal("invalid qualification accepted")
			}
		})
	}
}
