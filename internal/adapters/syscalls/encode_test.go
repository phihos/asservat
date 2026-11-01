package syscalls_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/manifest"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/artifact"
)

func testID(n int) string { return fmt.Sprintf("10000000-0000-4000-8000-%012x", n) }

// nativeCheck returns the repository's own syscallRecords stream validator
// (manifest.syscallCheck) for pod-uid over [from, from+1m].
func nativeCheck(t *testing.T, from time.Time) manifest.NativeCheck {
	t.Helper()
	v, err := manifest.New()
	if err != nil {
		t.Fatal(err)
	}
	d := artifact.Digest(sha256.Sum256([]byte("synthetic")))
	a := from.Add(-40 * time.Second) // recorder fixture: triggered 40s after the anchor
	e := artifact.ContextExpectation{
		Registration: artifact.Registration{Location: artifact.Location{ClusterID: testID(1), ArtifactID: testID(2), AttemptID: testID(3)}, StoreID: testID(4), AllocationID: testID(5), PoolRevision: 1, AllocationRevision: 1, NativeLimit: 64 << 20, AnchorAt: a, WriteUntil: a.Add(time.Minute), ExpiresAt: a.Add(2 * time.Minute), DeleteBy: a.Add(3 * time.Minute)},
		CaseID:       testID(6), OccurrenceID: testID(7), NodeUID: "node-uid", NodeBootID: testID(8), PodUID: "pod-uid", Namespace: "synthetic", NamespaceUID: "namespace-uid", WorkloadUID: "workload-uid", CollectorVersion: "synthetic-test", CollectorImageDigest: d, RecipeDigest: d, PlanDigest: d, CaptureUID: testID(9), ActionID: "a0123456789abcdef01234567", DataClass: "metadata", PurposeRef: "synthetic-test",
		Audience:            []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://identity.example.invalid", SubjectID: "synthetic-team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding-uid", AssignmentID: testID(10), BasisDigest: d}},
		RequestedAgeSeconds: 120, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 60, RetentionRules: []artifact.RetentionRule{{UID: "retention-uid", Generation: 1, Digest: d}}, TriggeredAt: from,
		NativeType: artifact.SyscallRecordsArtifact,
		Lifecycle:  &artifact.OngoingLifecycle{TriggerKind: "policy", SourceSessionID: testID(30), SourceStartedAt: from.Add(-35 * time.Second), SnapshotID: testID(31), RequestedBefore: 30 * time.Second, After: 10 * time.Second, HistoryCoverage: "full", GapReasons: []string{}, WindowCoverage: "full"},
	}
	c, err := v.NativeCheck(e, manifest.ContextManifest{StartedAt: from, CompletedAt: from.Add(time.Minute)})
	if err != nil {
		t.Fatal("native check fixture:", err)
	}
	return c
}

func TestEncodeJSONLinesMatchesSchema(t *testing.T) {
	from := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	boot := from.Add(-time.Hour) // CLOCK_BOOTTIME zero
	at := func(d time.Duration) uint64 { return uint64(time.Hour + d) }
	calls := []syscalls.Call{
		{Number: 0, Status: syscalls.Returned, PID: 10, EnteredBoot: at(time.Second), ExitedBoot: at(time.Second + 1500), Ret: 4096},
		{Number: 257, Status: syscalls.Returned, PID: 10, EnteredBoot: at(2 * time.Second), ExitedBoot: at(2 * time.Second), Ret: -2},
		{Number: 9, Status: syscalls.Returned, PID: 11, EnteredBoot: at(3 * time.Second), ExitedBoot: at(3*time.Second + 7), Ret: 0x7fffdeadb000},
		{Number: 0, Status: syscalls.Returned, PID: 11, EnteredBoot: at(3 * time.Second), ExitedBoot: at(3*time.Second + 7), Ret: -512},
		{Number: 231, Status: syscalls.NoReturn, PID: 12, EnteredBoot: at(4 * time.Second)},
		{Number: 7, Status: syscalls.Unfinished, PID: 13, EnteredBoot: at(5 * time.Second)},
		{Number: 1, Status: syscalls.Unmatched, PID: 14, ExitedBoot: at(6 * time.Second), Ret: -9},
		{Number: 0xfff, Status: syscalls.Returned, PID: 15, EnteredBoot: at(7 * time.Second), ExitedBoot: at(7*time.Second - 1), Ret: 0}, // exit before enter: no duration
	}
	var out bytes.Buffer
	if err := syscalls.EncodeJSONLines(&out, calls, syscalls.Meta{PodUID: "pod-uid", SourceEpoch: "epoch-7", BootWall: boot}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"identity":{"process_ref":"pid:10@epoch-7","thread_ref":"pid:10@epoch-7","pod_uid":"pod-uid"},"syscall":"read","abi":"x86_64","timestamp":"2026-10-09T12:00:01.0000015Z","duration_ns":1500,"outcome":"success"}`,
		`{"identity":{"process_ref":"pid:10@epoch-7","thread_ref":"pid:10@epoch-7","pod_uid":"pod-uid"},"syscall":"openat","abi":"x86_64","timestamp":"2026-10-09T12:00:02Z","duration_ns":0,"outcome":"error","errno":"ENOENT"}`,
		`{"identity":{"process_ref":"pid:11@epoch-7","thread_ref":"pid:11@epoch-7","pod_uid":"pod-uid"},"syscall":"mmap","abi":"x86_64","timestamp":"2026-10-09T12:00:03.000000007Z","duration_ns":7,"outcome":"success"}`,
		`{"identity":{"process_ref":"pid:11@epoch-7","thread_ref":"pid:11@epoch-7","pod_uid":"pod-uid"},"syscall":"read","abi":"x86_64","timestamp":"2026-10-09T12:00:03.000000007Z","duration_ns":7,"outcome":"error","errno":"ERESTARTSYS"}`,
		`{"identity":{"process_ref":"pid:12@epoch-7","thread_ref":"pid:12@epoch-7","pod_uid":"pod-uid"},"syscall":"exit_group","abi":"x86_64","timestamp":"2026-10-09T12:00:04Z","outcome":"unknown"}`,
		`{"identity":{"process_ref":"pid:13@epoch-7","thread_ref":"pid:13@epoch-7","pod_uid":"pod-uid"},"syscall":"poll","abi":"x86_64","timestamp":"2026-10-09T12:00:05Z","outcome":"unfinished"}`,
		`{"identity":{"process_ref":"pid:14@epoch-7","thread_ref":"pid:14@epoch-7","pod_uid":"pod-uid"},"syscall":"write","abi":"x86_64","timestamp":"2026-10-09T12:00:06Z","outcome":"unmatched"}`,
		`{"identity":{"process_ref":"pid:15@epoch-7","thread_ref":"pid:15@epoch-7","pod_uid":"pod-uid"},"syscall":"syscall_fff","abi":"x86_64","timestamp":"2026-10-09T12:00:06.999999999Z","outcome":"success"}`,
	}
	if got := out.String(); got != strings.Join(want, "\n")+"\n" {
		t.Fatalf("encoded:\n%s", got)
	}
	// The same streaming validator that checks stored native syscallRecords.
	for _, step := range []int{1, 17, out.Len()} {
		c := nativeCheck(t, from)
		b := out.Bytes()
		for len(b) > 0 {
			n := min(step, len(b))
			if err := c.Write(b[:n]); err != nil {
				t.Fatalf("native check rejected encoder output (step %d): %v", step, err)
			}
			b = b[n:]
		}
		if err := c.Close(); err != nil {
			t.Fatal("native check close:", err)
		}
		// A saved window's retained count is checked against this count.
		if n, ok := c.(interface{ PacketCount() uint64 }); !ok || n.PacketCount() != uint64(len(calls)) {
			t.Fatal("native check does not count validated events", ok)
		}
	}
	// The validator is live: the same calls for another pod are rejected.
	var foreign bytes.Buffer
	if err := syscalls.EncodeJSONLines(&foreign, calls, syscalls.Meta{PodUID: "other-pod", SourceEpoch: "epoch-7", BootWall: boot}); err != nil {
		t.Fatal(err)
	}
	if c := nativeCheck(t, from); c.Write(foreign.Bytes()) == nil && c.Close() == nil {
		t.Fatal("native check accepted a foreign pod")
	}
	// No argument or task-name content: every key is a schema field.
	for _, line := range want {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		for k := range m {
			if !strings.Contains(" identity syscall abi timestamp duration_ns outcome errno ", " "+k+" ") {
				t.Fatal("non-schema field", k)
			}
		}
	}
}

func TestEncodeJSONLinesRejects(t *testing.T) {
	boot := time.Date(2026, 10, 9, 11, 0, 0, 0, time.UTC)
	good := syscalls.Meta{PodUID: "pod-uid", SourceEpoch: "e", BootWall: boot}
	call := []syscalls.Call{{Status: syscalls.Returned, PID: 1, EnteredBoot: 1, ExitedBoot: 2}}
	for name, tc := range map[string]struct {
		m     syscalls.Meta
		calls []syscalls.Call
		err   error
	}{
		"empty pod":      {syscalls.Meta{SourceEpoch: "e", BootWall: boot}, call, syscalls.ErrMeta},
		"long pod":       {syscalls.Meta{PodUID: strings.Repeat("p", 65), SourceEpoch: "e", BootWall: boot}, call, syscalls.ErrMeta},
		"empty epoch":    {syscalls.Meta{PodUID: "p", BootWall: boot}, call, syscalls.ErrMeta},
		"long epoch":     {syscalls.Meta{PodUID: "p", SourceEpoch: strings.Repeat("e", 113), BootWall: boot}, call, syscalls.ErrMeta},
		"no boot anchor": {syscalls.Meta{PodUID: "p", SourceEpoch: "e"}, call, syscalls.ErrMeta},
		"zero status":    {good, []syscalls.Call{{PID: 1}}, syscalls.ErrRecord},
	} {
		if err := syscalls.EncodeJSONLines(&bytes.Buffer{}, tc.calls, tc.m); !errors.Is(err, tc.err) {
			t.Errorf("%s: %v, want %v", name, err, tc.err)
		}
	}
	// The longest allowed epoch plus a 10-digit pid stays within process_ref's 128.
	var out bytes.Buffer
	if err := syscalls.EncodeJSONLines(&out, []syscalls.Call{{Status: syscalls.NoReturn, PID: 0xffffffff, EnteredBoot: 1}}, syscalls.Meta{PodUID: "p", SourceEpoch: strings.Repeat("e", 112), BootWall: boot}); err != nil {
		t.Fatal(err)
	}
	var m struct {
		Identity struct {
			ProcessRef string `json:"process_ref"`
		} `json:"identity"`
	}
	if json.Unmarshal(out.Bytes(), &m) != nil || len(m.Identity.ProcessRef) > 128 {
		t.Fatal("process_ref", len(m.Identity.ProcessRef))
	}
}
