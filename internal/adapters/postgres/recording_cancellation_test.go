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
	if !recordingCancellationMatches(e, r, proof) {
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
			if recordingCancellationMatches(e, r, p) {
				t.Fatal("replacement proof accepted")
			}
		})
	}
	// ADR-313: every finite manual recording joins through the same proof.
	for _, mode := range []string{"syscall-metadata", "packet-metadata", "raw-packets", "http-headers"} {
		x := e
		recording := *e.Recording
		x.Recording = &recording
		x.Recording.Arguments = nil
		switch mode {
		case "syscall-metadata":
			x.NativeType, x.DataClass, x.Recording.Profile = artifact.SyscallRecordsArtifact, "metadata", "metadata"
		case "packet-metadata":
			x.NativeType, x.DataClass, x.Recording.Kind, x.Recording.Profile = artifact.PCAPNGArtifact, "metadata", "packetCapture", "networkHeaders"
		case "raw-packets":
			x.NativeType, x.Recording.Kind, x.Recording.Profile = artifact.RawPCAPNGArtifact, "packetCapture", "rawPackets"
		case "http-headers":
			x.NativeType, x.DataClass, x.Recording.Kind, x.Recording.Profile = artifact.HTTPHeadersArtifact, "extract", "packetCapture", "httpHeaders"
		}
		y := r
		y.ExpectationDigest = evidence.ContextExpectationDigest(x)
		p := proof
		p.ExpectationDigest = y.ExpectationDigest
		if !recordingCancellationExpected(x) || !recordingCancellationMatches(x, y, p) {
			t.Fatal("manual recording Stop refused", mode)
		}
		if recordingCancellationMatches(x, r, proof) {
			t.Fatal("other expectation digest accepted", mode)
		}
	}
	for _, mode := range []string{"no-recording", "snapshot", "profile", "logs"} {
		x := e
		switch mode {
		case "no-recording":
			x.Recording = nil
		case "snapshot":
			x.Snapshot = &artifact.SourceSnapshotRequest{}
		case "profile":
			x.Profile = &artifact.GoProfileAcquisition{}
		case "logs":
			x.Logs = &artifact.LogCapture{}
		}
		if recordingCancellationExpected(x) {
			t.Fatal("expectation with its own Stop proof accepted", mode)
		}
	}
}

// ADR-313: migration 00146 widens only the request rule from the argument
// recording to any Recording; Down restores the schema-145 function exactly.
func TestManualRecordingStopMigrationWidensOnlyRequestRule(t *testing.T) {
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
		return s[:strings.Index(s, "-- +goose StatementEnd")]
	}
	prior := definition("00142_pod_process_discovery.sql", true)
	if definition("00146_manual_recording_stop.sql", false) != prior {
		t.Fatal("Down changed the schema-145 Stop guard")
	}
	argument := "NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='syscallArguments' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='raw' AND convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Recording,Kind}'='syscallTrace' AND convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Recording,Profile}'='arguments' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb#>'{Recording,Arguments}')='object',false)"
	recording := "jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Recording') IS DISTINCT FROM 'object'"
	if strings.Count(prior, argument) != 1 || definition("00146_manual_recording_stop.sql", true) != strings.Replace(prior, argument, recording, 1) {
		t.Fatal("manual recording Stop changed fencing or joined-proof checks")
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
