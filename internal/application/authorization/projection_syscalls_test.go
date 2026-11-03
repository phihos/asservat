package authorization

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func newSyscallProjectionFixture(kind string, view analysis.SyscallView) (*projectionFixture, ContextProjectionAuthority, analysis.ContextProjectionScope) {
	f, service, scope := newProjectionFixture()
	source, _ := analysis.LookupProjectionSourceFor(kind, view.DisplayVersion())
	scope.NativeType, scope.SourceFormat, scope.DisplayVersion = kind, source.Format, source.DisplayVersion
	scope.SourceProjectionDigest, scope.Selection = artifact.Digest{}, analysis.LineSelection{}
	selection, _ := analysis.NormalizeSyscallSelection(scope.CaseID, scope.ArtifactID, view, "", 10, nil, false)
	scope.Syscalls = selection.Window()
	f.record.NativeType, f.record.SourceFormat, f.record.SourceProjectionDigest = kind, source.Format, source.ProjectionDigest
	f.record.DataClass, f.record.Retained.Input.EvidenceType = source.DataClass, "syscallTrace"
	f.record.Retained.Registration.NativeLimit = artifact.RecordingNativeLimit
	return f, service, scope
}

func TestSyscallProjectionAuthorityKeepsSourceSelectionAndOriginalBounds(t *testing.T) {
	for _, kind := range []string{artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact} {
		for _, view := range []analysis.SyscallView{analysis.SyscallSummaryView, analysis.SyscallEventsView} {
			t.Run(kind+"/"+string(view), func(t *testing.T) {
				f, service, scope := newSyscallProjectionFixture(kind, view)
				out, err := service.CheckProjectionCurrent(t.Context(), f, scope)
				if err != nil || !out.Valid(f.now) || out.Scope != scope || len(f.evidence) != 2 || f.evidence[0].DataClass != f.record.DataClass || f.evidence[0].Retained.Input.EvidenceType != "syscallTrace" {
					t.Fatal(out, err)
				}
				if !out.ValidUntil.Equal(f.record.ValidUntil) || !out.AccessUntil.Equal(f.retention.ExpiresAt) {
					t.Fatal("original bounds changed")
				}
			})
		}
	}
}

func TestSyscallProjectionAuthorityRefusesChangedOrExpiredInputs(t *testing.T) {
	for _, mode := range []string{"version", "source", "class", "view", "filter", "audience", "permissions", "after-block", "groups-after-block", "cancel-after-block"} {
		t.Run(mode, func(t *testing.T) {
			f, service, scope := newSyscallProjectionFixture(artifact.SyscallArgumentsArtifact, analysis.SyscallEventsView)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "version":
				f.record.Version[0]++
			case "source":
				f.record.NativeType = artifact.PprofArtifact
			case "class":
				f.record.DataClass = "metadata"
			case "view":
				scope.DisplayVersion = analysis.SyscallSummaryDisplayVersion
			case "filter":
				scope.Syscalls.Names[63] = "hidden"
			case "audience":
				f.record.Audience[0].AssignmentID = projectionTestID(99)
			case "permissions":
				f.permission.Allows = nil
			case "after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						f.now = f.now.Add(6 * time.Second)
					}
				}
			case "groups-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						f.identity.Groups = nil
					}
				}
			case "cancel-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						cancel()
					}
				}
			}
			if _, err := service.CheckProjectionCurrent(ctx, f, scope); err == nil {
				t.Fatal("invalid syscall authority admitted", mode)
			}
			if mode == "permissions" && f.counts["catalog"] != 0 {
				t.Fatal("catalog preceded current rights")
			}
		})
	}
}

func TestRawSyscallProjectionHasNoMetadataShareFallback(t *testing.T) {
	f, service, scope := newSyscallProjectionFixture(artifact.SyscallArgumentsArtifact, analysis.SyscallEventsView)
	shares := &projectionShares{now: func() time.Time { return f.now }}
	service.Shares = shares
	f.permission.Allows = nil
	if _, err := service.CheckProjectionCurrent(t.Context(), f, scope); err == nil || shares.reads != 0 || f.counts["catalog"] != 0 {
		t.Fatal("raw input gained metadata share fallback")
	}
}
