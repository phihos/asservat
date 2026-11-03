package analysis

import (
	"context"
	"strings"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type syscallRouteFixture struct {
	candidate value.ContextProjectionCandidate
}

func (r syscallRouteFixture) ResolveSyscallProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	return r.candidate, nil
}

func TestSyscallAdmissionBindsOriginalToolInputRouteAndResult(t *testing.T) {
	for _, kind := range []string{artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact} {
		for _, view := range []value.SyscallView{value.SyscallSummaryView, value.SyscallEventsView} {
			for _, mode := range []string{"pending", "ready", "disabled", "wrong-tool", "wrong-selection", "unacknowledged", "selection-in-route", "wrong-source", "cancelled", "wrong-result", "invalid-cursor", "underfunded-worker"} {
				t.Run(kind+"/"+string(view)+"/"+mode, func(t *testing.T) {
					f := newProjectionFixture(t)
					f.p.Profile.Worker.MemoryBytes, f.p.Profile.Worker.WorkerTransientBytes = value.SyscallProjectionWorkerBytes, value.SyscallProjectionWorkerBytes
					f.ready = mode == "ready" || mode == "wrong-result" || mode == "invalid-cursor"
					scope := &f.a.Scope
					selection, err := value.NormalizeSyscallSelection(scope.CaseID, scope.ArtifactID, view, "", 1, nil, false)
					if err != nil {
						t.Fatal(err)
					}
					source, _ := value.LookupProjectionSourceFor(kind, view.DisplayVersion())
					scope.NativeType, scope.SourceFormat, scope.SourceProjectionDigest, scope.DisplayVersion = source.NativeType, source.Format, source.ProjectionDigest, source.DisplayVersion
					scope.Selection, scope.Syscalls = value.LineSelection{}, selection.Window()
					candidate := scope.Candidate()
					candidate.Syscalls = value.SyscallWindow{}
					f.s.SyscallRoutes = syscallRouteFixture{candidate}
					f.s.Results.Reader = syscallReaderFixture{f, mode}
					request := value.SyscallQueryRequest{CaseID: scope.CaseID, ArtifactID: scope.ArtifactID, Selection: scope.Syscalls}
					invocation := f.invocation(scope.BeginTool())
					invocation.input = ContextQueryInput{Syscalls: request}
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					switch mode {
					case "underfunded-worker":
						f.p.Profile.Worker.WorkerTransientBytes = 8 << 20
					case "disabled":
						f.s.SyscallRoutes = nil
					case "wrong-tool":
						invocation.call.Tool = "get_file_excerpt"
					case "wrong-selection":
						invocation.input.Syscalls.Selection.Limit++
					case "unacknowledged":
						invocation.intentErr = value.ErrUnavailable
					case "selection-in-route":
						candidate.Syscalls = scope.Syscalls
						f.s.SyscallRoutes = syscallRouteFixture{candidate}
					case "wrong-source":
						candidate.NativeType = artifact.PprofArtifact
						f.s.SyscallRoutes = syscallRouteFixture{candidate}
					case "cancelled":
						cancel()
					}
					service, enabled := f.s.SyscallQueries()
					if enabled != (mode != "disabled") {
						t.Fatal("optional composition changed")
					}
					d, err := service.Begin(ctx, f, invocation, request)
					if mode == "wrong-result" || mode == "invalid-cursor" {
						if err == nil || d != nil || f.admissions != 1 || f.starts != 1 || f.reads != 1 {
							t.Fatal("invalid worker response was not refused after charging", err)
						}
						return
					}
					if mode != "pending" && mode != "ready" {
						if err == nil || d != nil || f.admissions+f.starts+f.reads != 0 {
							t.Fatal("effect preceded exact invocation/route", err)
						}
						return
					}
					if err != nil || d.Pending() != (mode == "pending") || d.Tool() != scope.BeginTool() || d.Association().Syscalls != scope.Syscalls || f.admissions != 1 || f.starts != 1 {
						t.Fatal("lost original syscall input", err)
					}
					summary, summaryReady := d.SyscallSummary()
					events, eventsReady := d.SyscallEvents()
					if summaryReady != (mode == "ready" && view == value.SyscallSummaryView) || eventsReady != (mode == "ready" && view == value.SyscallEventsView) || f.reads != boolInt(mode == "ready") {
						t.Fatal("wrong result readiness", summaryReady, eventsReady, f.reads)
					}
					if summaryReady {
						summary.Rows[0].Count = 99
						again, _ := d.SyscallSummary()
						if again.Rows[0].Count != 1 {
							t.Fatal("summary borrowed delivery data")
						}
					}
					if eventsReady {
						events.Events[0].Syscall = "write"
						*events.Events[0].DurationNS = 99
						again, _ := d.SyscallEvents()
						if again.Events[0].Syscall != "read" || *again.Events[0].DurationNS != 1 {
							t.Fatal("events borrowed delivery data")
						}
					}
					if err := d.Close(context.Background()); err != nil {
						t.Fatal(err)
					}
					if _, ok := d.SyscallSummary(); ok {
						t.Fatal("closed summary retained")
					}
					if _, ok := d.SyscallEvents(); ok {
						t.Fatal("closed events retained")
					}
				})
			}
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

type syscallReaderFixture struct {
	*projectionFixture
	mode string
}

func (f syscallReaderFixture) ReadProjection(ctx context.Context, start value.ContextReadStart, owner ContextProjectionRequestOwner) (ContextProjectionRead, error) {
	r, err := f.projectionFixture.ReadProjection(ctx, start, owner)
	if err != nil {
		return r, err
	}
	return syscallResultFixture{r, f.a.Scope, f.mode}, nil
}

type syscallResultFixture struct {
	ContextProjectionRead
	scope value.ContextProjectionScope
	mode  string
}

func (f syscallResultFixture) Projection(context.Context) (value.ProjectionResult, error) {
	if f.mode == "invalid-cursor" {
		return value.ProjectionResult{InvalidCursor: true}, nil
	}
	if f.mode == "wrong-result" {
		return value.ProjectionResult{Summary: &value.ProfileSummary{}}, nil
	}
	counts := value.SyscallRecordCounts{RecordCount: 1}
	if f.scope.Syscalls.View == value.SyscallSummaryView {
		return value.ProjectionResult{SyscallSummary: &value.SyscallSummaryPage{Version: f.scope.Version, Total: 1, Rows: []value.SyscallCount{{Syscall: "read", Count: 1}}, SyscallRecordCounts: counts}}, nil
	}
	duration := uint64(1)
	e := artifact.SyscallMetadataEvent{Identity: artifact.SyscallMetadataIdentity{ProcessRef: "p", ThreadRef: "t", PodUID: f.scope.PodUID}, Syscall: "read", ABI: "native", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Outcome: "success", DurationNS: &duration}
	return value.ProjectionResult{SyscallEvents: &value.SyscallEventPage{Version: f.scope.Version, TotalMatching: 1, Events: []artifact.SyscallMetadataEvent{e}, SyscallRecordCounts: counts}}, nil
}

func TestSyscallEncodedResultBoundIncludesEscapedMetadata(t *testing.T) {
	page := value.SyscallEventPage{Events: make([]artifact.SyscallMetadataEvent, 100)}
	for i := range page.Events {
		page.Events[i].Identity.ProcessRef = strings.Repeat("\x00", 128)
	}
	result := value.ProjectionResult{SyscallEvents: &page}
	if boundedSyscallResult(result) {
		t.Fatal("oversized encoded page accepted")
	}
	page.Events = page.Events[:1]
	if !boundedSyscallResult(result) {
		t.Fatal("bounded page refused")
	}
}
