package analysis

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func syscallResultFixture(t *testing.T, kind string, view SyscallView) (ContextProjectionScope, ProjectionResult) {
	t.Helper()
	s := testAuthority().Scope
	selection, err := NormalizeSyscallSelection(s.CaseID, s.ArtifactID, view, "", 1, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := LookupProjectionSourceFor(kind, view.DisplayVersion())
	s.NativeType, s.SourceFormat, s.SourceProjectionDigest, s.DisplayVersion = source.NativeType, source.Format, source.ProjectionDigest, source.DisplayVersion
	s.Selection, s.Syscalls = LineSelection{}, selection.Window()
	counts := SyscallRecordCounts{RecordCount: 2}
	if view == SyscallSummaryView {
		return s, ProjectionResult{SyscallSummary: &SyscallSummaryPage{Version: s.Version, Total: 2, Rows: []SyscallCount{{Syscall: "read", Count: 1}}, SyscallRecordCounts: counts}}
	}
	duration := uint64(4)
	e := artifact.SyscallMetadataEvent{Identity: artifact.SyscallMetadataIdentity{ProcessRef: "p", ThreadRef: "t", PodUID: s.PodUID}, Syscall: "read", ABI: "native", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Outcome: "success", DurationNS: &duration}
	return s, ProjectionResult{SyscallEvents: &SyscallEventPage{Version: s.Version, TotalMatching: 2, Events: []artifact.SyscallMetadataEvent{e}, SyscallRecordCounts: counts}}
}

func TestSyscallResultUnionAndContinuation(t *testing.T) {
	for _, kind := range []string{artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact} {
		for _, view := range []SyscallView{SyscallSummaryView, SyscallEventsView} {
			t.Run(kind+"/"+string(view), func(t *testing.T) {
				s, r := syscallResultFixture(t, kind, view)
				if !r.Valid(s) || s.ReadBatches() != 1 || s.BeginTool() != "get_syscall_"+string(view) {
					t.Fatal("valid result refused")
				}
				selection := s.Syscalls.Selection(s.CaseID, s.ArtifactID)
				var cursor string
				if r.SyscallSummary != nil {
					cursor = r.SyscallSummary.Next(selection, s.Version)
				} else {
					cursor = r.SyscallEvents.Next(selection, s.Version)
				}
				next, err := NormalizeSyscallSelection(s.CaseID, s.ArtifactID, view, cursor, 2, nil, false)
				if err != nil || next.Start != 1 || !next.Matches(s.Version) {
					t.Fatal("bad continuation", next, err)
				}
				for _, mutate := range []func(*ProjectionResult){
					func(r *ProjectionResult) { r.InvalidCursor = true },
					func(r *ProjectionResult) { r.TooLarge = true },
					func(r *ProjectionResult) { r.Summary = &ProfileSummary{} },
					func(r *ProjectionResult) {
						if r.SyscallSummary == nil {
							r.SyscallSummary = &SyscallSummaryPage{}
						} else {
							r.SyscallEvents = &SyscallEventPage{}
						}
					},
				} {
					bad := r
					mutate(&bad)
					if bad.Valid(s) {
						t.Fatal("mixed result accepted")
					}
				}
				for _, flags := range []ProjectionResult{{InvalidCursor: true}, {TooLarge: true}} {
					if !flags.Valid(s) {
						t.Fatal("empty refusal rejected")
					}
				}
				if (ProjectionResult{InvalidCursor: true, TooLarge: true}).Valid(s) || (ProjectionResult{}).Valid(s) {
					t.Fatal("ambiguous result accepted")
				}
				if r.Valid(testAuthority().Scope) {
					t.Fatal("syscall payload crossed legacy source")
				}
			})
		}
	}
}

func TestSyscallResultRejectsIncorrectCountsProvenanceAndFilters(t *testing.T) {
	for _, view := range []SyscallView{SyscallSummaryView, SyscallEventsView} {
		s, r := syscallResultFixture(t, artifact.SyscallRecordsArtifact, view)
		if view == SyscallSummaryView {
			for _, mutate := range []func(*SyscallSummaryPage){
				func(p *SyscallSummaryPage) { p.Version[0]++ },
				func(p *SyscallSummaryPage) { p.Start++ },
				func(p *SyscallSummaryPage) { p.Total = 3 },
				func(p *SyscallSummaryPage) { p.RecordCount = 1; p.Total = 1; p.Rows[0].Count = 2 },
				func(p *SyscallSummaryPage) { p.Total = 1 }, // whole-page counts must reconcile
				func(p *SyscallSummaryPage) { p.UnmatchedEvents = 3 },
				func(p *SyscallSummaryPage) { p.Rows[0].Errors = 2 },
				func(p *SyscallSummaryPage) { p.Rows[0].TotalDurationNS = 1 },
			} {
				p := CloneSyscallSummaryPage(*r.SyscallSummary)
				mutate(&p)
				if (ProjectionResult{SyscallSummary: &p}).Valid(s) {
					t.Fatal("invalid aggregate accepted", p)
				}
			}
		} else {
			for _, mutate := range []func(*SyscallEventPage){
				func(p *SyscallEventPage) { p.Version[0]++ },
				func(p *SyscallEventPage) { p.Start++ },
				func(p *SyscallEventPage) { p.TotalMatching = 3 },
				func(p *SyscallEventPage) { p.Events[0].Identity.PodUID = "other" },
				func(p *SyscallEventPage) { p.Events[0].Timestamp = "invalid" },
				func(p *SyscallEventPage) { *p.Events[0].DurationNS = artifact.MaxSyscallDurationNS + 1 },
			} {
				p := CloneSyscallEventPage(*r.SyscallEvents)
				mutate(&p)
				if (ProjectionResult{SyscallEvents: &p}).Valid(s) {
					t.Fatal("invalid event accepted", p)
				}
			}
			s.Syscalls.Names[0], s.Syscalls.NameCount = "write", 1
			if r.Valid(s) {
				t.Fatal("worker output ignored exact display filter")
			}
		}
	}
}

func TestSyscallResultClonesAndClearOwnTransientValues(t *testing.T) {
	_, r := syscallResultFixture(t, artifact.SyscallRecordsArtifact, SyscallEventsView)
	copy := CloneSyscallEventPage(*r.SyscallEvents)
	copy.Events[0].Syscall, *copy.Events[0].DurationNS = "write", 9
	if r.SyscallEvents.Events[0].Syscall != "read" || *r.SyscallEvents.Events[0].DurationNS != 4 {
		t.Fatal("clone borrowed nested values")
	}
	events := r.SyscallEvents.Events
	r.Clear()
	if events[0] != (artifact.SyscallMetadataEvent{}) || r.SyscallEvents != nil {
		t.Fatal("events retained after clear")
	}
	_, r = syscallResultFixture(t, artifact.SyscallRecordsArtifact, SyscallSummaryView)
	rows := r.SyscallSummary.Rows
	copySummary := CloneSyscallSummaryPage(*r.SyscallSummary)
	copySummary.Rows[0].Count++
	if rows[0].Count != 1 {
		t.Fatal("summary clone borrowed rows")
	}
	r.Clear()
	if rows[0] != (SyscallCount{}) || r.SyscallSummary != nil {
		t.Fatal("summary retained after clear")
	}
}

func TestSyscallQueryRequiresDeclaredAnalyzerCapacity(t *testing.T) {
	a := testAuthority()
	p := queryPlan(a)
	for _, kind := range []string{artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact} {
		scope, _ := syscallResultFixture(t, kind, SyscallSummaryView)
		if p.Matches(scope) {
			t.Fatal("small legacy declaration authorized syscall analyzer")
		}
		p.Profile.Worker.MemoryBytes = SyscallProjectionWorkerBytes
		if p.Matches(scope) {
			t.Fatal("physical memory replaced declared transient capacity")
		}
		p.Profile.Worker.WorkerTransientBytes = SyscallProjectionWorkerBytes
		if !p.Matches(scope) || !p.Matches(a.Scope) {
			t.Fatal("bounded shared worker refused")
		}
		p = queryPlan(a)
	}
}

func TestSyscallEmptyPageClonePreservesClosedWireShape(t *testing.T) {
	events := CloneSyscallEventPage(SyscallEventPage{Events: []artifact.SyscallMetadataEvent{}})
	summary := CloneSyscallSummaryPage(SyscallSummaryPage{Rows: []SyscallCount{}})
	if events.Events == nil || summary.Rows == nil {
		t.Fatal("empty approved arrays became JSON null")
	}
	if CloneSyscallEventPage(SyscallEventPage{}).Events != nil || CloneSyscallSummaryPage(SyscallSummaryPage{}).Rows != nil {
		t.Fatal("missing branch became a populated array")
	}
}
