package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	capacity "asservat.local/asservat/internal/application/capacity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	plan "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestManualProcessesActualPublicInputCompilerAndFunding(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-processes")
	if !installedProcessesFocus() || installedRecordingFocus() || installedLogsFocus() || !installedFastFixture() || installedClusterCount() != 2 || nativeCapacityProfile().Records != 8 || installedProcessesQueryUnits != 4 {
		t.Fatal("ordinary process focus/topology/original backing drift")
	}
	if !slices.Contains(installedConsoleScopes(), "evidence:read") {
		t.Fatal("console lacks ordinary read")
	}
	storedBytes, objects := installedRegionalContextReserve()
	native := artifact.Registration{NativeLimit: artifact.ProcessNativeLimit}
	history := artifact.Registration{NativeLimit: 128 << 10}
	if storedBytes < 2*(native.ReservedBytes()+history.ReservedBytes()) || objects < 16 {
		t.Fatal("two original process captures and history not backed", storedBytes, objects)
	}
	qualified, source := installedProfileComparisonCapacityFixture(t, *nativeCapacityProfile())
	pool, err := capacity.CompileProtectedPoolPlan(source, "capacity")
	if err != nil {
		t.Fatal(err)
	}
	backing, err := capacity.CompileQualifiedRootBacking(qualified, pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, digest := backing.Canonical()
	root := capacity.RootConfiguration{Format: capacity.RootConfigurationFormat, RootID: qualified.RootBacking.RootID, AttemptID: custodyID(), PlanDigest: digest, Revision: 1, InitialObservedAt: now, InitialUntil: now.Add(5 * time.Second), RevisionObservedAt: now, RevisionUntil: now.Add(5 * time.Second), PlannedUntil: now.Add(time.Duration(qualified.RootBacking.AdmissionSeconds) * time.Second), ReservedAt: now, CaptureBackedAt: &now, ReadyAt: &now}
	if _, err := capacity.CompileQueryBacking(qualified, root, backing, pool, artifact.Digest{1}, custodyID()); err != nil {
		t.Fatal("process original query units not backed", err)
	}
	cluster := "00000000-0000-4000-8000-000000000001"
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	input := manualProcessesArguments(cluster, "payments", "api")
	raw, _ := json.Marshal(input)
	if err := wire.ValidateInput("preview_capture", raw); err != nil {
		t.Fatal("actual authored public input", err)
	}
	var public contracts.CaptureComposition
	b, _ := json.Marshal(input["profile_composition"])
	if json.Unmarshal(b, &public) != nil {
		t.Fatal("public composition decode")
	}
	composition, err := conversion.CompositionFromWire(public)
	if err != nil {
		t.Fatal(err)
	}
	target := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: targets.Request{ClusterID: cluster, Namespace: configuration.NamespaceRef{Name: "payments", UID: "namespace"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "namespace", Name: "api-a", UID: "pod", ControllerUID: "replicaset"}, PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "policies", Generation: 1, Digest: artifact.Digest{1}}, Complete: true, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 600, MaximumSeconds: 3600, DeletionBudgetSeconds: 10}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "processSnapshot", RequestedSeconds: 600, AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.CompileRecorder(plan.RecorderInput{CaptureID: cluster, Executor: identity.Principal{Issuer: "https://identity.example.test", Subject: "requester", ClientID: "mcp", Kind: identity.Human}, Target: target, Composition: *composition, Retention: retention, Deadline: now.Add(time.Minute), NodeRecorder: true}, nil, now)
	if err != nil || !compiler.AcceptableProcesses(compiled).Acceptable() || compiled.Approval != nil || len(compiled.Actions) != 1 || compiled.Actions[0].Kind != "processSnapshot" || compiled.Actions[0].MaxBytes != artifact.ProcessNativeLimit || compiled.Actions[0].Timeout != "5s" {
		t.Fatal("actual ordinary process compiler", err)
	}
}

func installedProcessNativeUnit(t *testing.T) ([]byte, artifact.ProcessInventory, core.Pod, savedProcessesBrowserSource, installedProcessesPage) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	boot := "00000000-0000-4000-8000-000000000001"
	p := artifact.ProcessInventory{Format: artifact.ProcessFormat, PodUID: "pod", NodeUID: "node", NodeBootID: boot, Mode: artifact.ProcessAll, StartedAt: now, CompletedAt: now.Add(time.Millisecond), Origins: []artifact.ProcessOrigin{}, Processes: []artifact.ProcessRecord{}, Gaps: []string{"socketOwnersUnsupported"}}
	pod := core.Pod{ObjectMeta: meta.ObjectMeta{UID: "pod"}}
	source := savedProcessesBrowserSource{CaptureID: custodyID(), ArtifactID: custodyID(), Version: strings.Repeat("01", 32)}
	page := installedProcessesPage{Kind: "discoveryPage", CaptureID: source.CaptureID, ArtifactIDs: []string{source.ArtifactID}, Section: "processes", Processes: []installedProcessesRow{}, Gaps: slices.Clone(p.Gaps)}
	for i, letter := range []string{"a", "b"} {
		id := "containerd://" + strings.Repeat(letter, 64)
		pid := uint32(100 + i)
		p.Origins = append(p.Origins, artifact.ProcessOrigin{RuntimeID: id, MainPID: pid, Outcome: "observed"})
		r := artifact.ProcessRecord{Identity: artifact.ProcessIdentity{PodUID: p.PodUID, NodeBootID: boot, RuntimeID: id, HostPID: pid, StartTimeTicks: 100, CgroupPath: "/pod/" + strings.Repeat(letter, 64), CgroupID: uint64(i + 1)}, NamespacePID: 1, ObservedAt: now, Main: true, State: "S", Threads: 1, ExecutablePath: "/provider-proxy"}
		p.Processes = append(p.Processes, r)
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, core.ContainerStatus{Name: letter, ContainerID: id, State: core.ContainerState{Running: &core.ContainerStateRunning{}}})
		raw, _ := json.Marshal(r.Identity)
		h := sha256.New()
		h.Write([]byte("process-ref/v1\x00" + source.CaptureID + source.ArtifactID))
		version, _ := hex.DecodeString(source.Version)
		h.Write(version)
		h.Write(raw)
		row := installedProcessesRow{ProcessRef: hex.EncodeToString(h.Sum(nil)), PodUID: "pod", DisplayPID: 1, ExecutablePath: r.ExecutablePath, Runtime: "unknown", ObservedAt: now}
		row.IdentityBasis.Confidence = "observed"
		row.IdentityBasis.Reason = "exact observed identity"
		page.Processes = append(page.Processes, row)
	}
	if !p.Valid() {
		t.Fatal("synthetic native shape")
	}
	raw, _ := json.Marshal(p)
	page.Summary.StartedAt, page.Summary.EndedAt = p.StartedAt, p.CompletedAt
	page.Summary.RetainedBytes = int64(len(raw))
	page.Summary.CaptureMode = "none"
	page.Summary.Coverage.RequestedPods = 1
	page.Summary.Coverage.CoveredPods = 1
	page.Summary.Coverage.InventoryComplete = true
	page.Summary.Coverage.StopReason = "completed"
	return raw, p, pod, source, page
}
func TestManualProcessesNativeParityBindsRuntimeKernelAndApprovedRows(t *testing.T) {
	native, inventory, pod, source, page := installedProcessNativeUnit(t)
	if err := checkInstalledProcessOrigins(inventory, pod); err != nil {
		t.Fatal(err)
	}
	if err := checkInstalledProcessPage(native, source, page); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*installedProcessesPage){func(p *installedProcessesPage) { p.Processes[0].ProcessRef = strings.Repeat("f", 64) }, func(p *installedProcessesPage) { p.Processes[0].DisplayPID = 100 }, func(p *installedProcessesPage) { p.Processes[0].ExecutablePath = "/different" }, func(p *installedProcessesPage) { p.Summary.Coverage.CoveredPods = 0 }, func(p *installedProcessesPage) { p.Summary.WireBytes = 1 }, func(p *installedProcessesPage) { p.Processes = p.Processes[:1] }, func(p *installedProcessesPage) { p.Processes[0], p.Processes[1] = p.Processes[1], p.Processes[0] }} {
		b, _ := json.Marshal(page)
		var changed installedProcessesPage
		_ = json.Unmarshal(b, &changed)
		mutate(&changed)
		if checkInstalledProcessPage(native, source, changed) == nil {
			t.Fatal("altered approved row/coverage accepted")
		}
	}
	pod.Status.ContainerStatuses[0].ContainerID = "containerd://" + strings.Repeat("c", 64)
	if checkInstalledProcessOrigins(inventory, pod) == nil {
		t.Fatal("runtime replacement accepted")
	}
	if checkInstalledProcessPage(append(bytes.Clone(native), []byte("{}")...), source, page) == nil {
		t.Fatal("native tail bypassed")
	}
}
func TestManualProcessesStopDoesNotClaimFastTerminalAsCancellation(t *testing.T) {
	read := func(name string, args, out any) {
		b, _ := json.Marshal(map[string]any{"capture_id": "original", "phase": "Succeeded", "revision": 1})
		if json.Unmarshal(b, out) != nil {
			t.Fatal("fixture decode")
		}
	}
	if qualifyManualProcessesStop(t, context.Background(), "original", read, func(string, any) (installedJourneyEnvelope, string) {
		t.Fatal("fast terminal issued cancellation")
		return installedJourneyEnvelope{}, ""
	}) {
		t.Fatal("fast completion falsely qualified blocked-source Stop")
	}
}

func TestManualProcessesStopRetainsOriginalRevisionAndJoinedNoArtifact(t *testing.T) {
	reads, cancelled := 0, false
	read := func(name string, args, out any) {
		reads++
		phase := "Running"
		if cancelled {
			phase = "Cancelled"
		}
		raw, _ := json.Marshal(map[string]any{"capture_id": "original", "phase": phase, "revision": 7})
		if name != "get_capture" || json.Unmarshal(raw, out) != nil {
			t.Fatal("unexpected Stop read")
		}
	}
	invoke := func(name string, args any) (installedJourneyEnvelope, string) {
		input, ok := args.(map[string]any)
		if !ok || name != "cancel_capture" || input["capture_id"] != "original" || input["expected_revision"] != int64(7) || input["idempotency_key"] != "stop-processes-original" {
			t.Fatal("Stop replaced original revision/identity", args)
		}
		cancelled = true
		raw, _ := json.Marshal(map[string]any{"capture_id": "original", "cancellation_requested": true})
		return installedJourneyEnvelope{Status: "ok", Data: raw}, ""
	}
	if !qualifyManualProcessesStop(t, context.Background(), "original", read, invoke) || reads != 2 || !cancelled {
		t.Fatal("Stop did not await positive joined terminal")
	}
}
