package analysis

import (
	"context"
	"fmt"
	"strings"
	"testing"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type profileRouteFixture struct {
	candidate value.ContextProjectionCandidate
}

func (r profileRouteFixture) ResolveProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	return r.candidate, nil
}

// Synthetic admitted backing verifies only typed invocation/route composition;
// production profile funding and worker parsing remain deliberately unavailable.
func TestProfileSummaryAdmissionBindsOriginalToolInputAndRoute(t *testing.T) {
	for _, mode := range []string{"pending", "ready", "disabled", "wrong-tool", "wrong-selection", "unacknowledged", "source-in-route", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newProjectionFixture(t)
			f.ready = mode == "ready"
			f.s.Results.Reader = profileReaderFixture{f}
			scope := &f.a.Scope
			scope.NativeType, scope.SourceFormat, scope.DisplayVersion = artifact.PprofArtifact, artifact.PprofFormat, value.ProfileSummaryDisplayVersion
			scope.SourceProjectionDigest, scope.Selection, scope.Profile = artifact.Digest{}, value.LineSelection{}, value.ProfileSummarySelection{SampleType: "cpu", TopN: 20}
			candidate := scope.Candidate()
			candidate.NativeType, candidate.Profile = "", value.ProfileSummarySelection{}
			f.s.ProfileRoutes = profileRouteFixture{candidate}
			request := value.ProfileSummaryRequest{CaseID: scope.CaseID, ArtifactID: scope.ArtifactID, Selection: scope.Profile}
			invocation := f.invocation("get_profile_summary")
			invocation.input = ContextQueryInput{Profile: request}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "disabled":
				f.s.ProfileRoutes = nil
			case "wrong-tool":
				invocation.call.Tool = "get_file_excerpt"
			case "wrong-selection":
				invocation.input.Profile.Selection.SampleType = "alloc_space"
			case "unacknowledged":
				invocation.intentErr = value.ErrUnavailable
			case "source-in-route":
				candidate.NativeType = artifact.GoTraceArtifact
				f.s.ProfileRoutes = profileRouteFixture{candidate}
			case "cancelled":
				cancel()
			}
			service, enabled := f.s.ProfileSummaries()
			if enabled != (mode != "disabled") {
				t.Fatal("optional composition changed")
			}
			result, err := service.Begin(ctx, f, invocation, request)
			if mode != "pending" && mode != "ready" {
				if err == nil || result != nil || f.admissions+f.starts+f.reads != 0 {
					t.Fatal("effect preceded exact invocation/route", err)
				}
				return
			}
			if err != nil || result.Pending() != (mode == "pending") || result.Tool() != "get_profile_summary" || result.Association().Profile != scope.Profile || f.admissions != 1 || f.starts != 1 {
				t.Fatal("summary lost original input", err)
			}
			defer result.Close(context.Background())
			summary, ready := result.ProfileSummary()
			if ready != (mode == "ready") || ready && (summary.SampleType != "cpu" || f.reads != 1) || !ready && f.reads != 0 {
				t.Fatal("summary readiness/read count", ready, f.reads)
			}

		})
	}
}

func TestProfileResultIndependentlyBoundsEncodedWorkerOutput(t *testing.T) {
	selection := value.ProfileSummarySelection{SampleType: "cpu", TopN: 100}
	summary := value.ProfileSummary{SampleType: "cpu", Unit: "nanoseconds", Total: 100, Top: []value.ProfileHotspot{}, SymbolStatus: "complete"}
	for i := range 100 {
		name, fraction := fmt.Sprintf("%03d%s", i, strings.Repeat("x", 509)), .01
		summary.Top = append(summary.Top, value.ProfileHotspot{Function: &name, Flat: 1, Cumulative: 1, Fraction: &fraction})
	}
	if !summary.Valid(selection) {
		t.Fatal("fixture is not structurally valid")
	}
	if boundedProfileSummary(&summary, selection) {
		t.Fatal("oversized encoded result accepted")
	}
	summary.Top = summary.Top[:1]
	if !boundedProfileSummary(&summary, selection) {
		t.Fatal("bounded result rejected")
	}
}

// The component fake supplies only a closed result, never parser or SQL proof.
type profileReaderFixture struct{ *projectionFixture }

func (f profileReaderFixture) ReadProjection(ctx context.Context, start value.ContextReadStart, owner ContextProjectionRequestOwner) (ContextProjectionRead, error) {
	r, err := f.projectionFixture.ReadProjection(ctx, start, owner)
	if err != nil {
		return r, err
	}
	return profileResultFixture{r}, nil
}

type profileResultFixture struct{ ContextProjectionRead }

func (f profileResultFixture) Projection(context.Context) (value.ProjectionResult, error) {
	return value.ProjectionResult{Summary: &value.ProfileSummary{SampleType: "cpu", Unit: "nanoseconds", Top: []value.ProfileHotspot{}, SymbolStatus: "missing"}}, nil
}
