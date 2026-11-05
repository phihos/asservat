package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"
	"unicode/utf8"

	logcodec "asservat.local/asservat/internal/adapters/logs"
	capacity "asservat.local/asservat/internal/application/capacity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	plan "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
)

func TestManualLogsActualPublicInputCompilerAndFunding(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-logs")
	if !installedLogsFocus() || installedRecordingFocus() || !installedFastFixture() || installedClusterCount() != 2 || nativeCapacityProfile().Records != installedLogsQueryUnits || installedLogsQueryUnits != 40 {
		t.Fatal("API-only logs focus/cost/topology drift")
	}
	if !slices.Contains(installedConsoleScopes(), "evidence:raw") || !slices.Contains(installedConsoleScopes(), "acr") {
		t.Fatal("actual console scope producer lacks logs raw/step-up")
	}
	bytes, objects := installedRegionalContextReserve()
	if bytes != 40*1544192 || objects != 160 {
		t.Fatal("logs original prepaid backing changed", bytes, objects)
	}
	p := *nativeCapacityProfile()
	q, source := installedProfileComparisonCapacityFixture(t, p)
	pool, err := capacity.CompileProtectedPoolPlan(source, "capacity")
	if err != nil {
		t.Fatal(err)
	}
	backing, err := capacity.CompileQualifiedRootBacking(q, pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, digest := backing.Canonical()
	root := capacity.RootConfiguration{Format: capacity.RootConfigurationFormat, RootID: q.RootBacking.RootID, AttemptID: custodyID(), PlanDigest: digest, Revision: 1, InitialObservedAt: now, InitialUntil: now.Add(5 * time.Second), RevisionObservedAt: now, RevisionUntil: now.Add(5 * time.Second), PlannedUntil: now.Add(time.Duration(q.RootBacking.AdmissionSeconds) * time.Second), ReservedAt: now, CaptureBackedAt: &now, ReadyAt: &now}
	queries, err := capacity.CompileQueryBacking(q, root, backing, pool, artifact.Digest{1}, custodyID())
	if err != nil {
		t.Fatal("40 configured logs units not originally backed", err)
	}
	total := backing.Totals()
	if total.SystemObjects.Objects+queries.Reservation.SystemObjects.Objects != 19712 || pool.System.Objects != 20000 || pool.Burst.Objects != 30000 || pool.Capacity.Objects != 100000 {
		t.Fatal("combined original object partition drift")
	}
	const cluster = "00000000-0000-4000-8000-000000000001"
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	for _, stop := range []bool{false, true} {
		input := manualLogsArguments(cluster, "payments", "api", stop)
		raw, _ := json.Marshal(input)
		if err := wire.ValidateInput("preview_capture", raw); err != nil {
			t.Fatal("logs actual authored preview contract", err)
		}
		var public contracts.CaptureComposition
		b, _ := json.Marshal(input["profile_composition"])
		if json.Unmarshal(b, &public) != nil {
			t.Fatal("composition decode")
		}
		c, err := conversion.CompositionFromWire(public)
		if err != nil {
			t.Fatal(err)
		}
		target := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: targets.Request{ClusterID: cluster, Namespace: configuration.NamespaceRef{Name: "payments", UID: "namespace"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "namespace", Name: "api-a", UID: "pod", ControllerUID: "replicaset"}, PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "policies", Generation: 1, Digest: artifact.Digest{1}}, Complete: true, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 600, MaximumSeconds: 3600, DeletionBudgetSeconds: 10}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "logs", RequestedSeconds: 600, AnchorAt: now}, now)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range []bool{false, true} {
			in := plan.RecorderInput{CaptureID: cluster, Executor: identity.Principal{Issuer: "https://identity.example.test", Subject: "requester", ClientID: "mcp", Kind: identity.Human}, Target: target, Composition: *c, Retention: retention, Deadline: now.Add(time.Minute), NodeRecorder: true, RequireApproval: required}
			compiled, err := compiler.CompileRecorder(in, nil, now)
			if err != nil || !compiler.AcceptableLogs(compiled).Acceptable() || len(compiled.Actions) != 1 || (compiled.Approval != nil) != required {
				t.Fatal("logs actual builtin compiler/explicit protected review", err)
			}
			a := compiled.Actions[0]
			if a.Kind != "logs" || a.Before != "1h" || a.LogStream != "both" || a.MaxBytes != installedLogsNativeLimit {
				t.Fatal("logs authored source bound changed")
			}
			if stop && (a.After != "30s" || a.Timeout != "40s") || !stop && (a.After != "2s" || a.Timeout != "15s") {
				t.Fatal("logs Stop/complete lifetime drift")
			}
		}
	}
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "approved-recording")
	if nativeCapacityProfile().Records != 8 {
		t.Fatal("unrelated native fixture budget changed")
	}
	system, burst := installedCapacityObjectPartitions()
	if system != 10000 || burst != 40000 {
		t.Fatal("unrelated object partition changed")
	}
}

func manualLogsNativeUnit(t *testing.T) ([]byte, installedLogsPage, savedLogsBrowserSource) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	anchor := now.Add(-time.Second)
	var native bytes.Buffer
	encoder, err := logcodec.NewEncoder(t.Context(), &native, artifact.LogHeader{Record: "header", Format: artifact.LogFormat, PodUID: "original-pod", WindowStart: anchor.Add(-time.Hour), WindowEnd: anchor, Origins: 1}, installedLogsNativeLimit)
	if err != nil {
		t.Fatal(err)
	}
	origin := artifact.LogOrigin{Record: "origin", OriginID: 0, ContainerKind: "regular", ContainerName: "app", Source: "current", Stream: "combined"}
	if err := encoder.BeginOrigin(origin); err != nil {
		t.Fatal(err)
	}
	if _, err := encoder.Write([]byte("synthetic\n\xff\x00\n")); err != nil {
		t.Fatal(err)
	}
	if err := encoder.EndOrigin(artifact.LogCoverage{Record: "coverage", OriginID: 0, FetchOutcome: "complete", FetchStartedAt: &now, FetchFinishedAt: &now, Gaps: []string{"rotationUnknown"}}); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	source := savedLogsBrowserSource{CaseID: "00000000-0000-4000-8000-000000000001", ArtifactID: "00000000-0000-4000-8000-000000000002", Version: "0100000000000000000000000000000000000000000000000000000000000000", PodUID: "original-pod", GrantID: "00000000-0000-4000-8000-000000000003", Expires: now.Add(time.Minute)}
	selection, _ := query.NormalizeLogSelection(source.CaseID, source.ArtifactID, "", 100)
	e := artifact.ContextExpectation{NativeType: artifact.LogsArtifact, DataClass: "raw", PodUID: source.PodUID, ActionID: "a0123456789abcdef01234567", TriggeredAt: anchor, Logs: &artifact.LogCapture{ActionID: "a0123456789abcdef01234567", BeforeMillis: 3600000, Streams: "combined", TimeoutMillis: 10000, MaxNativeBytes: installedLogsNativeLimit}, Registration: artifact.Registration{NativeLimit: installedLogsNativeLimit}}
	result, err := logcodec.QueryLogs(t.Context(), bytes.NewReader(native.Bytes()), e, now, now, selection, artifact.Digest{1})
	if err != nil || result.Logs == nil {
		t.Fatal("synthetic native projector", err)
	}
	raw := result.Logs
	page := installedLogsPage{Kind: "logs", PodUID: source.PodUID, WindowStart: raw.WindowStart, WindowEnd: raw.WindowEnd, Entries: make([]installedLogsEntry, 0), Observed: now, Expires: now.Add(20 * time.Second)}
	page.Coverage.Origins, page.Coverage.Complete, page.Coverage.Partial, page.Coverage.Unavailable = raw.OriginCount, raw.CompleteOrigins, raw.PartialOrigins, raw.UnavailableOrigins
	page.Coverage.SourceBytes, page.Coverage.Fragments, page.Coverage.Unknown, page.Coverage.Gapped = raw.SourceBytes, raw.TotalFragments, raw.UnknownTimestampOrigins, raw.GappedOrigins
	for _, r := range raw.Entries {
		var entry installedLogsEntry
		entry.Origin.OriginID, entry.Origin.ContainerKind, entry.Origin.ContainerName, entry.Origin.Source, entry.Origin.Stream = r.Origin.OriginID, r.Origin.ContainerKind, r.Origin.ContainerName, r.Origin.Source, r.Origin.Stream
		entry.Origin.RuntimeID, entry.Origin.RestartCount = r.Origin.RuntimeID, r.Origin.RestartCount
		entry.Fragment, entry.Line, entry.Offset, entry.LineOffset, entry.Continuation, entry.EndLine, entry.SourceTime = r.Fragment, r.Line, r.Offset, r.LineOffset, r.Continuation, r.EndLine, r.SourceTime
		b, _ := base64.StdEncoding.DecodeString(r.Data)
		if utf8.Valid(b) {
			s := string(b)
			entry.Text = &s
		} else {
			s := r.Data
			entry.BytesBase64 = &s
		}
		page.Entries = append(page.Entries, entry)
	}
	return native.Bytes(), page, source
}
func TestManualLogsNativeParityRejectsChangedBytesOriginAndCoverage(t *testing.T) {
	native, page, _ := manualLogsNativeUnit(t)
	if _, err := checkInstalledLogsParity(native, page.PodUID, page); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"byte", "origin", "coverage", "offset", "pod"} {
		b, _ := json.Marshal(page)
		var changed installedLogsPage
		_ = json.Unmarshal(b, &changed)
		switch mode {
		case "byte":
			s := "replacement"
			changed.Entries[0].Text = &s
		case "origin":
			changed.Entries[0].Origin.Stream = "stdout"
		case "coverage":
			changed.Coverage.SourceBytes++
		case "offset":
			changed.Entries[0].Offset++
		case "pod":
			changed.PodUID = "replacement"
		}
		if _, err := checkInstalledLogsParity(native, page.PodUID, changed); err == nil {
			t.Fatal("native parity accepted changed data", mode)
		}
	}
}
func TestManualLogsImmediatePageStillReplaysOriginalBeginWithoutAnotherRead(t *testing.T) {
	_, page, source := manualLogsNativeUnit(t)
	calls, paid, verified := 0, 0, 0
	body, _ := json.Marshal(page)
	ready := installedComparisonReply{installedJourneyEnvelope: installedJourneyEnvelope{Status: "ok", RequestID: "00000000-0000-4000-8000-000000000004", DataClass: "raw", Data: body}}
	provenance, _ := json.Marshal([]map[string]string{{"artifactID": source.ArtifactID, "digest": source.Version}})
	_ = json.Unmarshal(provenance, &ready.Provenance)
	request := installedLogsRequest(source, "original-key")
	saved, _ := json.Marshal(request)
	call := func(name string, in any) installedComparisonReply {
		calls++
		if name != "get_logs" {
			t.Fatal("immediate page incurred paid poll")
		}
		got, _ := json.Marshal(in)
		if !bytes.Equal(got, saved) {
			t.Fatal("replay request changed")
		}
		if calls == 1 {
			paid++
			return ready
		}
		pending, _ := json.Marshal(map[string]any{"query_handle": "00000000-0000-4000-8000-000000000005", "query_observed_at": page.Observed.Add(time.Millisecond), "query_expires_at": page.Expires, "retry_after_seconds": 1})
		return installedComparisonReply{installedJourneyEnvelope: installedJourneyEnvelope{Status: "pending", RequestID: "00000000-0000-4000-8000-000000000006", DataClass: "raw", Data: pending}}
	}
	got := queryInstalledLogsWithCall(t, context.Background(), source, request, call, func(handle, operation string) func() {
		verified++
		if handle != "00000000-0000-4000-8000-000000000005" || operation != ready.RequestID {
			t.Fatal("original query/call binding")
		}
		return func() {}
	}, true)
	if calls != 2 || paid != 1 || verified != 1 || !reflect.DeepEqual(got, page) {
		t.Fatal("ready replay replaced page/charges")
	}
}

// Synthetic advancing clock over the actual shared installed helper. Both live
// proofs happen before waiting; only original terminal joins are deferred.
func TestManualLogsRollingOriginalTwoSlots(t *testing.T) {
	now, active, peak, snapshots := 0, 0, 0, 0
	var joined []int
	p := &installedPacketTerminalPipeline{limit: installedLogsQueries}
	originalDeadlines := []int{60, 72}
	for index := 0; index < installedLogsQueries; index++ {
		if active >= 2 {
			t.Fatal("third worker admitted before an original joined")
		}
		id, deadline := index, originalDeadlines[index]
		active++
		peak = max(peak, active)
		now += 12
		snapshots++
		p.add(t, func() {
			if originalDeadlines[id] != deadline {
				t.Fatal("original worker deadline changed")
			}
			now = max(now, deadline)
			active--
			joined = append(joined, id)
		})
	}
	if p.admitted != 2 || p.joined != 0 || len(p.pending) != 2 || snapshots != 2 || now != 24 {
		t.Fatal("proofs deferred or originals prematurely joined")
	}
	p.finish(t)
	if p.admitted != 2 || p.joined != 2 || len(p.pending) != 0 || active != 0 || peak != 2 || now != 72 || !reflect.DeepEqual(joined, []int{0, 1}) {
		t.Fatal("two funded original workers lost FIFO/join/deadline", p, joined, now)
	}
}
