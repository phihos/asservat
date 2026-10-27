package artifact

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"
	"time"
)

func TestNativeTypeRegistry(t *testing.T) {
	safe := regexp.MustCompile(`^artifact-[0-9a-f-]{36}\.[a-z]+$`)
	names, formats := map[string]bool{}, map[string]bool{}
	for _, name := range []string{PodStatusArtifact, PCAPNGArtifact, SyscallRecordsArtifact, HTTPHeadersArtifact} {
		nt, ok := LookupNativeType(name)
		if !ok || names[nt.Name] || formats[nt.Format] || nt.MaxBytes < 1 || nt.MaxBytes > StreamingNativeLimit || len(nt.DataClasses) == 0 || !safe.MatchString(nt.Filename("10000000-0000-4000-8000-000000000002")) || nt.Coverage == "" {
			t.Fatal("registry entry", name, nt)
		}
		if (Binding{ClusterID: "10000000-0000-4000-8000-000000000001", ArtifactID: "10000000-0000-4000-8000-000000000002", AttemptID: "10000000-0000-4000-8000-000000000003", MediaType: nt.MediaType}).Validate() != nil {
			t.Fatal("media type is not a valid binding", nt.MediaType)
		}
		names[nt.Name], formats[nt.Format] = true, true
		back, ok := NativeTypeForFormat(nt.Format)
		if !ok || back.Name != name {
			t.Fatal("format lookup", nt.Format)
		}
	}
	// The historical pod-status values are unchanged.
	pod, _ := LookupNativeType(PodStatusArtifact)
	if pod.MediaType != "application/json" || pod.Format != ContextFormat || pod.Extension != ".json" || pod.MaxBytes != MaxContextBytes || pod.Coverage != "Selected pod-status fields only; no logs, messages or workload configuration." || !pod.AllowsClass("raw") {
		t.Fatal("pod-status type changed", pod)
	}
	pcap, _ := LookupNativeType(PCAPNGArtifact)
	if pcap.MediaType != "application/x-pcapng" || pcap.Extension != ".pcapng" || pcap.Kind != "packetCapture" || pcap.AllowsClass("raw") {
		t.Fatal("pcapng type", pcap)
	}
	httpType, _ := LookupNativeType(HTTPHeadersArtifact)
	if httpType.MediaType == pcap.MediaType || httpType.Extension == pcap.Extension {
		t.Fatal("HTTP header JSON would be labelled as a packet capture")
	}
	if _, ok := LookupNativeType("core"); ok {
		t.Fatal("unregistered type accepted")
	}
	if _, ok := NativeTypeForFormat("pcap"); ok {
		t.Fatal("unregistered format accepted")
	}
	pcap.DataClasses[0] = "raw"
	if again, _ := LookupNativeType(PCAPNGArtifact); again.AllowsClass("raw") {
		t.Fatal("lookup shares registry state")
	}
}

func validLifecycle(t0 time.Time) OngoingLifecycle {
	return OngoingLifecycle{TriggerKind: "policy", SourceSessionID: "10000000-0000-4000-8000-000000000010", SourceStartedAt: t0.Add(-time.Minute), SnapshotID: "10000000-0000-4000-8000-000000000011", RequestedBefore: 30 * time.Second, After: 10 * time.Second, HistoryCoverage: "full", GapReasons: []string{}, WindowCoverage: "full"}
}

func TestOngoingLifecycleCoverageRules(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	if err := validLifecycle(t0).Validate(t0); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*OngoingLifecycle){
		"armed after t0-before claims full history": func(l *OngoingLifecycle) { l.SourceStartedAt = t0.Add(-29 * time.Second) },
		"partial history without a reason":          func(l *OngoingLifecycle) { l.HistoryCoverage = "partial"; l.WindowCoverage = "partial" },
		"full window after a known early stop":      func(l *OngoingLifecycle) { l.SourceStoppedAt = t0.Add(2 * time.Second) },
		"full window with a gap":                    func(l *OngoingLifecycle) { l.GapReasons = []string{"unknownLoss"} },
		"full window with partial history": func(l *OngoingLifecycle) {
			l.HistoryCoverage = "partial"
			l.GapReasons = []string{"warming"}
		},
		"stop before start": func(l *OngoingLifecycle) {
			l.SourceStoppedAt = l.SourceStartedAt.Add(-time.Second)
			l.WindowCoverage = "partial"
		},
		"save without origin": func(l *OngoingLifecycle) { l.TriggerKind = "recordingSave"; l.After = 0 },
		"save with post window": func(l *OngoingLifecycle) {
			l.TriggerKind = "recordingSave"
			l.Origin = &RecordingSaveOrigin{"policy-uid", Digest{1}}
		},
		"origin outside a save":      func(l *OngoingLifecycle) { l.Origin = &RecordingSaveOrigin{"policy-uid", Digest{1}} },
		"natural crash is onTrigger": func(l *OngoingLifecycle) { l.TriggerKind = "naturalCrash" },
		"duplicate reason": func(l *OngoingLifecycle) {
			l.HistoryCoverage = "none"
			l.WindowCoverage = "none"
			l.GapReasons = []string{"warming", "warming"}
		},
		"unknown reason": func(l *OngoingLifecycle) {
			l.HistoryCoverage = "none"
			l.WindowCoverage = "none"
			l.GapReasons = []string{"guess"}
		},
		"unknown coverage":       func(l *OngoingLifecycle) { l.WindowCoverage = "mostly" },
		"empty window":           func(l *OngoingLifecycle) { l.RequestedBefore, l.After = 0, 0 },
		"sub-millisecond window": func(l *OngoingLifecycle) { l.After = 1500 * time.Microsecond },
		"window beyond ring ceiling": func(l *OngoingLifecycle) {
			l.RequestedBefore = 2 * time.Hour
			l.SourceStartedAt = t0.Add(-3 * time.Hour)
		},
		"no source session": func(l *OngoingLifecycle) { l.SourceSessionID = "" },
	}
	for name, change := range cases {
		l := validLifecycle(t0)
		change(&l)
		if l.Validate(t0) == nil {
			t.Fatal("accepted:", name)
		}
	}
	// Valid incomplete cases: an exit at t0+2s keeps full history but a
	// partial window; a recording save has no post window.
	gone := validLifecycle(t0)
	gone.SourceStoppedAt, gone.WindowCoverage, gone.GapReasons = t0.Add(2*time.Second), "partial", []string{"targetGone"}
	save := validLifecycle(t0)
	save.TriggerKind, save.After, save.Origin = "recordingSave", 0, &RecordingSaveOrigin{"policy-uid", Digest{1}}
	warming := validLifecycle(t0)
	warming.SourceStartedAt, warming.HistoryCoverage, warming.WindowCoverage, warming.GapReasons = t0.Add(-10*time.Second), "partial", "partial", []string{"warming"}
	for _, l := range []OngoingLifecycle{gone, save, warming} {
		if err := l.Validate(t0); err != nil {
			t.Fatal("rejected valid coverage", l, err)
		}
	}
	c := save.Clone()
	c.Origin.PolicyUID = "changed"
	c.GapReasons = append(c.GapReasons, "x")
	if save.Origin.PolicyUID != "policy-uid" || len(save.GapReasons) != 0 {
		t.Fatal("clone shares state")
	}
}

func TestLifecycleDurationMatchesSchemaPattern(t *testing.T) {
	pattern := regexp.MustCompile(`^(0s|[1-9][0-9]*(ms|s|m|h|d))$`)
	for d, want := range map[time.Duration]string{0: "0s", 30 * time.Second: "30s", 90 * time.Second: "90s", 2 * time.Minute: "2m", 1500 * time.Millisecond: "1500ms", time.Hour: "1h"} {
		if got := LifecycleDuration(d); got != want || !pattern.MatchString(got) {
			t.Fatal(d, got, want)
		}
	}
}

func typedExpectation(t *testing.T, kind string, limit int64) ContextExpectation {
	t.Helper()
	a := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	d := Digest{1}
	return ContextExpectation{NativeType: kind, Registration: Registration{Location: Location{ClusterID: "10000000-0000-4000-8000-000000000001", ArtifactID: "10000000-0000-4000-8000-000000000002", AttemptID: "10000000-0000-4000-8000-000000000003"}, StoreID: "10000000-0000-4000-8000-000000000004", AllocationID: "10000000-0000-4000-8000-000000000005", PoolRevision: 1, AllocationRevision: 1, NativeLimit: limit, AnchorAt: a, WriteUntil: a.Add(time.Minute), ExpiresAt: a.Add(2 * time.Minute), DeleteBy: a.Add(3 * time.Minute)},
		CaseID: "10000000-0000-4000-8000-000000000006", OccurrenceID: "10000000-0000-4000-8000-000000000007", NodeUID: "node", NodeBootID: "10000000-0000-4000-8000-000000000008", PodUID: "pod", Namespace: "ns", NamespaceUID: "ns-uid", WorkloadUID: "workload", CollectorVersion: "v", CollectorImageDigest: d, RecipeDigest: d, PlanDigest: d, CaptureUID: "10000000-0000-4000-8000-000000000009", ActionID: "a0123456789abcdef01234567", DataClass: "metadata", PurposeRef: "p",
		Audience: []AudienceAssignment{{Kind: "Group", Issuer: "https://id.invalid", SubjectID: "team", Role: "r", BasisKind: "AccessBinding", BasisUID: "b", AssignmentID: "10000000-0000-4000-8000-00000000000a", BasisDigest: d}}, RequestedAgeSeconds: 120, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 60, RetentionRules: []RetentionRule{{UID: "r", Generation: 1, Digest: d}}, TriggeredAt: a.Add(time.Second)}
}

func TestTypedExpectationBounds(t *testing.T) {
	pod := typedExpectation(t, PodStatusArtifact, MaxContextBytes)
	if pod.Validate() != nil || pod.Binding().MediaType != "application/json" {
		t.Fatal("pod status")
	}
	// Existing serialized expectations and their digests are unchanged.
	b, _ := json.Marshal(pod)
	if bytes.Contains(b, []byte("NativeType")) || bytes.Contains(b, []byte("Lifecycle")) {
		t.Fatal("pod-status expectation serialization changed", string(b))
	}
	pcap := typedExpectation(t, PCAPNGArtifact, StreamingNativeLimit)
	if pcap.Validate() != nil || pcap.Binding().MediaType != "application/x-pcapng" {
		t.Fatal("256 MiB PCAPNG expectation", pcap.Validate())
	}
	l := validLifecycle(pcap.TriggeredAt)
	pcap.Lifecycle = &l
	if pcap.Validate() != nil {
		t.Fatal("ongoing PCAPNG save")
	}
	for name, change := range map[string]func(*ContextExpectation){
		"pod status above 4 KiB": func(e *ContextExpectation) {
			e.NativeType = PodStatusArtifact
			e.Lifecycle = nil
			e.Registration.NativeLimit = MaxContextBytes + 1
		},
		"pod status from a source": func(e *ContextExpectation) {
			e.NativeType = PodStatusArtifact
			e.Registration.NativeLimit = MaxContextBytes
		},
		"above streaming bound": func(e *ContextExpectation) { e.Registration.NativeLimit = StreamingNativeLimit + 1 },
		"HTTP projection limit": func(e *ContextExpectation) { e.NativeType = HTTPHeadersArtifact },
		"raw packets":           func(e *ContextExpectation) { e.DataClass = "raw" },
		"unknown type":          func(e *ContextExpectation) { e.NativeType = "core" },
		"API class recorder":    func(e *ContextExpectation) { e.ExecutionClass, e.NodeUID, e.NodeBootID = ContextAPIExecution, "", "" },
		"invalid coverage":      func(e *ContextExpectation) { e.Lifecycle.WindowCoverage = "most" },
	} {
		x := pcap
		x.Lifecycle = pcap.Lifecycle.Clone()
		change(&x)
		if x.Validate() == nil {
			t.Fatal("accepted:", name)
		}
	}
}

// A full 33-part journal must fit migration 00061's 16 KiB jsonb state bound,
// including jsonb's text spacing after every ':' and ','.
func TestStreamingStateFitsJournalAtLimit(t *testing.T) {
	p := streamingTestPlan(t, StreamingNativeLimit)
	s := StreamingState{CreateSpent: true, UploadID: string(bytes.Repeat([]byte("u"), 200)), CompleteSpent: true, Receipt: &CopyReceipt{VersionID: string(bytes.Repeat([]byte("v"), 64)), ETag: `"` + string(bytes.Repeat([]byte("e"), 40)) + `"`}, ReleasedAt: time.Now()}
	var total int64
	for i := 1; i <= p.PartLimit(); i++ {
		n := StreamingPartBytes
		if i == p.PartLimit() {
			n = p.TemporaryBytes() - total
		}
		s.Parts = append(s.Parts, StreamingPart{Number: i, Bytes: n, SHA256: Digest{255, 255, 255}, ETag: `"` + string(bytes.Repeat([]byte("e"), 40)) + `"`})
		total += n
	}
	for i := range s.Parts {
		for j := range s.Parts[i].SHA256 {
			s.Parts[i].SHA256[j] = 255
		}
	}
	s.CompleteBytes, s.CompleteSHA256 = total, s.Parts[0].SHA256
	s.Receipt.Bytes, s.Receipt.SHA256 = total, s.CompleteSHA256
	if err := s.Validate(p); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	spaced := len(b) + bytes.Count(b, []byte(",")) + bytes.Count(b, []byte(":"))
	if len(s.Parts) != StreamingMaxParts || spaced > 16384 {
		t.Fatal("journal state exceeds its SQL bound", len(s.Parts), spaced)
	}
}
