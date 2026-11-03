package postgres

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	execution "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/migrations"
)

func TestArgumentProgressOffersStopButRequestRemainsNonterminal(t *testing.T) {
	f := progressFactsFixture(t, "pending")
	var e artifact.ContextExpectation
	if err := json.Unmarshal(f.ContextCapture.ExpectationJson, &e); err != nil {
		t.Fatal(err)
	}
	e.ExecutionClass, e.NodeUID, e.NodeBootID = artifact.ContextAPIExecution, "", ""
	e.NativeType, e.DataClass, e.ActionID = artifact.SyscallArgumentsArtifact, "raw", "a111111111111111111111111"
	e.Registration.NativeLimit = artifact.RecordingNativeLimit
	e.Recording = &artifact.Recording{Kind: "syscallTrace", Profile: "arguments", Composition: []byte("{}"), DurationMillis: 1000, MaxBytes: 64 << 10, Syscalls: &artifact.RecordingSyscalls{Names: []string{"close"}, MaxEvents: 1000, MaxEventsPerSecond: 100, MaxTrackedThreads: 64}, Arguments: &artifact.RecordingArguments{ProgramDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AccountingRule: artifact.Digest{3}, MaxProbeBytes: 256, MaxBytesPerEvent: 1, MaxBytesPerSecond: 25600}}
	if err := e.Validate(); err != nil {
		t.Fatal("argument progress fixture", err)
	}
	f.ContextCapture.ExpectationJson, _ = json.Marshal(e)
	f.RequestDigest = digest(normalized(e.Registration))
	out, err := progressFacts(f)
	if err != nil || !out.CanCancel {
		t.Fatal("finite arguments lack public Stop affordance", out, err)
	}
	f.ContextCapture.SnapshotCancelRequestedAt = f.ContextCapture.CreatedAt
	out, err = progressFacts(f)
	if err != nil || out.CanCancel || !out.CancellationRequested || out.Phase == "Cancelled" {
		t.Fatal("request alone reported joined", out, err)
	}
	f.ContextCapture.SnapshotCancelJoinedAt = f.ContextCapture.CreatedAt
	out, err = progressFacts(f)
	if err != nil || out.Phase != "Cancelled" || out.ReasonCode != "CancellationJoined" {
		t.Fatal("argument join acquired profile uncertainty", out, err)
	}
}

func TestArgumentCancellationMatchesOnlyOriginalRawWriter(t *testing.T) {
	row := argumentObservationRowFixture()
	e := artifact.ContextExpectation{CaptureUID: uid(row.CaptureID), NativeType: artifact.SyscallArgumentsArtifact, DataClass: "raw", Registration: artifact.Registration{Location: artifact.Location{AttemptID: uid(row.AttemptID)}}, Recording: &artifact.Recording{Kind: "syscallTrace", Profile: "arguments", Arguments: &artifact.RecordingArguments{}}}
	r := execution.APIExecution{Process: execution.APIProcessBinding{PodUID: uid(row.RootID), ProcessEpoch: uid(row.GrantID)}, ExpectationDigest: evidence.ContextExpectationDigest(e)}
	proof := artifact.RecordingCancellation{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, WriterPodUID: r.Process.PodUID, WriterEpoch: r.Process.ProcessEpoch, ExpectationDigest: r.ExpectationDigest, JoinedAt: time.Now()}
	if !argumentCancellationMatches(e, r, proof) {
		t.Fatal("original raw writer refused")
	}
	for name, edit := range map[string]func(*artifact.RecordingCancellation){
		"capture":      func(p *artifact.RecordingCancellation) { p.CaptureID = uid(row.ID) },
		"attempt":      func(p *artifact.RecordingCancellation) { p.AttemptID = uid(row.ID) },
		"pod":          func(p *artifact.RecordingCancellation) { p.WriterPodUID = uid(row.ID) },
		"epoch":        func(p *artifact.RecordingCancellation) { p.WriterEpoch = uid(row.ID) },
		"digest":       func(p *artifact.RecordingCancellation) { p.ExpectationDigest[0] ^= 1 },
		"missing-join": func(p *artifact.RecordingCancellation) { p.JoinedAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			p := proof
			edit(&p)
			if argumentCancellationMatches(e, r, p) {
				t.Fatal("replacement proof accepted")
			}
		})
	}
	for _, mode := range []string{"metadata", "profile", "missing-arguments", "snapshot", "wrong-kind"} {
		x := e
		recording := *e.Recording
		x.Recording = &recording
		switch mode {
		case "metadata":
			x.DataClass = "metadata"
		case "profile":
			x.NativeType = artifact.PprofArtifact
		case "missing-arguments":
			x.Recording.Arguments = nil
		case "snapshot":
			x.Snapshot = &artifact.SourceSnapshotRequest{}
		case "wrong-kind":
			x.Recording.Kind = "packetCapture"
		}
		if argumentCancellationExpected(x) {
			t.Fatal("nonargument expectation accepted", mode)
		}
	}
}

func TestArgumentCancellationMigrationRestoresProfileGuard(t *testing.T) {
	definition := func(name string, up bool) string {
		t.Helper()
		raw, err := fs.ReadFile(migrations.Files(), name)
		if err != nil {
			t.Fatal(err)
		}
		before, after, ok := strings.Cut(string(raw), "-- +goose Down")
		if !ok {
			t.Fatal("missing Down")
		}
		s := before
		if !up {
			s = after
		}
		start := strings.Index(s, "CREATE OR REPLACE FUNCTION guard_snapshot_cancel()")
		if start < 0 {
			t.Fatal("missing Stop guard")
		}
		s = s[start:]
		end := strings.Index(s, "-- +goose StatementEnd")
		if end < 0 {
			t.Fatal("missing statement end")
		}
		return s[:end]
	}
	prior := definition("00124_profile_cancellation.sql", true)
	if definition("00129_syscall_arguments_processing.sql", false) != prior {
		t.Fatal("Down changed original profile/snapshot Stop")
	}
	current := definition("00129_syscall_arguments_processing.sql", true)
	start := strings.Index(current, " AND NOT COALESCE(convert_from(NEW.expectation_json")
	if start < 0 {
		t.Fatal("missing narrow argument addition")
	}
	end := strings.Index(current[start:], ",false)")
	if end < 0 || current[:start]+current[start+end+len(",false)"):] != prior {
		t.Fatal("argument Stop changed existing fencing or joined-proof checks")
	}
}
