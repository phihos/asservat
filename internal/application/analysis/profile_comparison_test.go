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

const comparisonSourceID = "22222222-2222-4222-8222-222222222222"

type comparisonServiceFixture struct {
	*projectionFixture
	routes                [2]value.ContextProjectionCandidate
	pair                  [2]value.ContextQueryPlan
	routeCalls, planCalls int
	result                value.ProjectionResult
	resultErr             error
}

func newComparisonServiceFixture(t *testing.T) (*comparisonServiceFixture, value.ProfileComparisonRequest) {
	t.Helper()
	f := newProjectionFixture(t)
	f.p.Profile.Worker.MemoryBytes, f.p.Profile.Worker.WorkerTransientBytes = value.ProfileComparisonWorkerBytes, value.ProfileComparisonWorkerBytes
	s := &f.a.Scope
	s.NativeType, s.SourceFormat, s.DisplayVersion = artifact.PprofArtifact, artifact.PprofFormat, value.ProfileComparisonDisplayVersion
	s.SourceProjectionDigest, s.Selection, s.Profile = artifact.Digest{}, value.LineSelection{}, value.ProfileSummarySelection{SampleType: "cpu", TopN: 20}
	s.Comparison = value.ProfileComparisonWindow{Normalization: value.ProfileComparisonRate, Baseline: value.ProfileComparisonBaseline{CaseID: comparisonSourceID, ArtifactID: comparisonSourceID, CaptureID: comparisonSourceID, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: "baseline-workload", PodUID: "baseline-pod", Version: artifact.Digest{5}}}
	b := f.a
	b.Scope, _ = s.BaselineScope()
	b.Environment.Location.ArtifactID = comparisonSourceID
	b.Environment.Processing.Location = b.Environment.Location
	b.Environment.Processing.CaptureID = comparisonSourceID
	b.Environment.Path.ID = comparisonSourceID
	b.Retention.WorkloadUID, b.Retention.PodUID = b.Scope.WorkloadUID, b.Scope.PodUID
	f.a.Baseline = &b
	baselinePlan := f.p
	baselinePlan.AllocationID = comparisonSourceID
	baselinePlan.WorkloadUID, baselinePlan.Profile.Path = b.Scope.WorkloadUID, b.Environment.Path
	c := &comparisonServiceFixture{projectionFixture: f, pair: [2]value.ContextQueryPlan{baselinePlan, f.p}}
	for i, source := range [2]value.ContextProjectionScope{b.Scope, *s} {
		route := source.Candidate()
		route.NativeType, route.Profile, route.Comparison = "", value.ProfileSummarySelection{}, value.ProfileComparisonWindow{}
		c.routes[i] = route
	}
	c.result.Comparison = comparisonDisplayFixture()
	f.s.ComparisonRoutes, f.s.Plans, f.s.Results.Reader = c, c, c
	if !f.a.Valid(f.now) || !value.ProfileComparisonPlansMatch(*s, c.pair[0], c.pair[1]) {
		t.Fatal("invalid synthetic comparison composition")
	}
	return c, value.ProfileComparisonRequest{CaseID: s.CaseID, ArtifactID: s.ArtifactID, BaselineCaseID: b.Scope.CaseID, BaselineArtifactID: b.Scope.ArtifactID, Selection: s.Comparison.Selection(s.Profile)}
}
func comparisonDisplayFixture() *value.ProfileComparison {
	name, duration := "example.work", 2.0
	facts := value.ProfileComparisonFacts{ProfileComparisonAcquisition: value.ProfileComparisonAcquisition{ProfileType: "cpu", Mode: "interval"}, DurationSeconds: &duration, Total: 10, Period: &value.ProfileComparisonPeriod{Type: "cpu", Unit: "nanoseconds", Value: 100}, SymbolStatus: "complete"}
	return &value.ProfileComparison{SampleType: "cpu", Unit: "nanoseconds", Normalization: value.ProfileComparisonRate, Aggregation: "cumulative", Comparable: true, Baseline: facts, Incident: facts, BuildStatus: "unknown", SamplingStatus: "same", AcquisitionStatus: "same", Rows: []value.ProfileComparisonRow{{Function: &name, Baseline: 5, Incident: 5, Delta: 0}}, Limitations: []string{"A short sample does not establish a regression."}}
}
func (f *comparisonServiceFixture) ResolveProjectionRoute(_ context.Context, caseID, artifactID string, _ identity.Identity, _ artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	f.routeCalls++
	for _, c := range f.routes {
		if c.CaseID == caseID && c.ArtifactID == artifactID {
			return c, nil
		}
	}
	return value.ContextProjectionCandidate{}, value.ErrUnavailable
}
func (f *comparisonServiceFixture) ContextComparisonPlans(context.Context, value.ContextProjectionAuthority) ([2]value.ContextQueryPlan, error) {
	f.planCalls++
	return f.pair, nil
}
func (f *comparisonServiceFixture) ContextQueryPlan(context.Context, value.ContextProjectionAuthority) (value.ContextQueryPlan, error) {
	panic("comparison fell back to single plan")
}
func (f *comparisonServiceFixture) ReadProjection(ctx context.Context, start value.ContextReadStart, owner ContextProjectionRequestOwner) (ContextProjectionRead, error) {
	r, err := f.projectionFixture.ReadProjection(ctx, start, owner)
	if err != nil {
		return r, err
	}
	return comparisonReadFixture{ContextProjectionRead: r, result: f.result, err: f.resultErr}, nil
}

type comparisonReadFixture struct {
	ContextProjectionRead
	result value.ProjectionResult
	err    error
}

func (r comparisonReadFixture) Projection(context.Context) (value.ProjectionResult, error) {
	return r.result, r.err
}

func TestProfileComparisonServiceBindsTwoRoutesPlansAndOriginalInput(t *testing.T) {
	for _, mode := range []string{"pending", "ready", "disabled", "missing-pair-plans", "wrong-input", "wrong-tool", "baseline-source-selection", "baseline-version", "incident-source-selection", "bad-baseline-account", "underfunded", "cancelled", "wrong-source-version"} {
		t.Run(mode, func(t *testing.T) {
			f, request := newComparisonServiceFixture(t)
			f.ready = mode == "ready"
			invocation := f.invocation("compare_profiles")
			invocation.input = ContextQueryInput{Comparison: request}
			ctx, stop := context.WithCancel(t.Context())
			defer stop()
			switch mode {
			case "disabled":
				f.s.ComparisonRoutes = nil
			case "missing-pair-plans":
				f.s.Plans = f.projectionFixture
			case "wrong-input":
				invocation.input.Comparison.BaselineArtifactID = projectionID
			case "wrong-tool":
				invocation.call.Tool = "get_profile_summary"
			case "baseline-source-selection":
				f.routes[0].Profile = f.a.Scope.Profile
			case "baseline-version":
				f.routes[0].Comparison.Baseline.Version = artifact.Digest{9}
			case "incident-source-selection":
				f.routes[1].NativeType = artifact.PprofArtifact
			case "bad-baseline-account":
				f.pair[0].AccountID = comparisonSourceID
			case "underfunded":
				f.pair[0].Profile.Worker.WorkerTransientBytes = value.ProfileSummaryWorkerBytes
			case "cancelled":
				stop()
			case "wrong-source-version":
				f.a.Scope.Comparison.Baseline.Version[0]++
			}
			service, enabled := f.s.ProfileComparisons()
			if enabled != (mode != "disabled") {
				t.Fatal("optional facet changed")
			}
			d, err := service.Begin(ctx, f, invocation, request)
			if mode != "pending" && mode != "ready" {
				if err == nil || d != nil || f.admissions+f.starts+f.reads != 0 {
					t.Fatal("effect preceded exact pair validation", err)
				}
				return
			}
			if err != nil || d == nil || d.Pending() != (mode == "pending") || f.routeCalls != 2 || f.planCalls != 1 || f.admissions != 1 || f.starts != 1 || d.Tool() != "compare_profiles" || d.Association().Comparison != request.Selection {
				t.Fatal("comparison lost normalized input/backing", err)
			}
			baseline, incident, ok := d.ProfileComparisonSources()
			if !ok || baseline.CaseID != request.BaselineCaseID || baseline.ArtifactID != request.BaselineArtifactID || baseline.Version != f.a.Baseline.Scope.Version || incident.ArtifactID != request.ArtifactID || incident.Version != f.a.Scope.Version {
				t.Fatal("independently pinned provenance changed")
			}
			if _, ready := d.ProfileComparison(); ready != (mode == "ready") {
				t.Fatal("result readiness changed")
			}
			if _, summary := d.ProfileSummary(); summary {
				t.Fatal("comparison exposed single summary")
			}
			if err := d.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, _, ok := d.ProfileComparisonSources(); ok {
				t.Fatal("closed delivery exposed provenance")
			}
		})
	}
}

func TestProfileComparisonPaidPollRetainsResultOwnerAndDeepClones(t *testing.T) {
	f, request := newComparisonServiceFixture(t)
	f.ready = false
	begin := f.invocation("compare_profiles")
	begin.input = ContextQueryInput{Comparison: request}
	service, _ := f.s.ProfileComparisons()
	pending, err := service.Begin(t.Context(), f, begin, request)
	if err != nil {
		t.Fatal(err)
	}
	id := pending.Association().QueryID
	if err := pending.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.ready = true
	poll := f.invocation("get_query_result")
	d, err := f.s.Results.GetQueryResult(t.Context(), f, poll, id)
	if err != nil || d == nil || f.starts != 1 || f.admissions != 1 || f.polls != 1 || f.reads != 1 || !f.active {
		t.Fatal("poll acquired/replaced worker or lost paid result", err)
	}
	copy, ok := d.ProfileComparison()
	if !ok {
		t.Fatal("comparison missing")
	}
	*copy.Rows[0].Function = "changed"
	*copy.Baseline.DurationSeconds = 99
	copy.Incident.Period.Value = 99
	copy.Limitations[0] = "changed"
	original, ok := d.ProfileComparison()
	if !ok || *original.Rows[0].Function == "changed" || *original.Baseline.DurationSeconds == 99 || original.Incident.Period.Value == 99 || original.Limitations[0] == "changed" {
		t.Fatal("getter leaked mutable result")
	}
	if err := d.CheckDisclosure(t.Context()); err == nil {
		t.Fatal("unacknowledged result disclosed")
	}
	poll.outcome = d
	if err := d.CheckDisclosure(t.Context()); err != nil {
		t.Fatal("acknowledged result lost original authority", err)
	}
	rows := d.comparison.Rows
	if !d.RefuseOversizedResult() || d.Refusal() != ContextProjectionRecordTooLarge || f.completions != 0 || f.lastRead.closed || !f.active || rows[0] != (value.ProfileComparisonRow{}) {
		t.Fatal("restrictive transition lost owner or retained content")
	}
	if _, ok := d.ProfileComparison(); ok {
		t.Fatal("size refusal exposed result")
	}
	if err := d.Close(context.Background()); err != nil || f.completions != 1 || f.active {
		t.Fatal("size refusal cleanup", err)
	}
	if _, ok := d.ProfileComparison(); ok {
		t.Fatal("closed result exposed content")
	}
}

func TestProfileComparisonMismatchRetainsChargedOwnerUntilAcknowledgedClose(t *testing.T) {
	f, request := newComparisonServiceFixture(t)
	f.result = value.ProjectionResult{IncompatibleProfiles: true}
	invocation := f.invocation("compare_profiles")
	invocation.input = ContextQueryInput{Comparison: request}
	service, _ := f.s.ProfileComparisons()
	d, err := service.Begin(t.Context(), f, invocation, request)
	if err != nil || d == nil || d.Pending() || d.Refusal() != ContextProjectionIncompatibleProfiles || d.Effect() != ContextQueryReadCharged || f.completions != 0 || f.lastRead.closed || !f.active {
		t.Fatal("typed mismatch lost charged owner", err)
	}
	if _, ok := d.ProfileComparison(); ok {
		t.Fatal("mismatch disclosed content")
	}
	if d.RefuseOversizedResult() {
		t.Fatal("prepared mismatch changed refusal")
	}
	if err := d.CheckDisclosure(t.Context()); err == nil {
		t.Fatal("mismatch bypassed outcome acknowledgement")
	}
	invocation.outcome = d
	if err := d.CheckDisclosure(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(context.Background()); err != nil || f.completions != 1 || f.active {
		t.Fatal("mismatch cleanup", err)
	}
}

func TestProfileComparisonResultRefusesMalformedMixedAndOversizedWorkerOutput(t *testing.T) {
	for _, mode := range []string{"mixed-mismatch", "single-summary", "oversized", "native-error"} {
		t.Run(mode, func(t *testing.T) {
			f, request := newComparisonServiceFixture(t)
			switch mode {
			case "mixed-mismatch":
				f.result.IncompatibleProfiles = true
			case "single-summary":
				f.result = value.ProjectionResult{Summary: &value.ProfileSummary{}}
			case "native-error":
				f.resultErr = value.ErrProfileIncompatible
			case "oversized":
				request.Selection.TopN = 100
				f.a.Scope.Profile.TopN, f.a.Baseline.Scope.Profile.TopN = 100, 100
				r := f.result.Comparison
				r.Rows = nil
				for i := range 100 {
					name := fmt.Sprintf("%03d%s", i, strings.Repeat("x", 509))
					r.Rows = append(r.Rows, value.ProfileComparisonRow{Function: &name, Baseline: 5, Incident: 5})
				}
				if !r.Valid(request.Selection) || boundedProfileComparison(r, request.Selection) {
					t.Fatal("invalid maximum encoded fixture")
				}
			}
			invocation := f.invocation("compare_profiles")
			invocation.input = ContextQueryInput{Comparison: request}
			service, _ := f.s.ProfileComparisons()
			d, err := service.Begin(t.Context(), f, invocation, request)
			if err == nil || d != nil || f.reads != 1 || !f.lastRead.closed || f.completions != 1 || f.active {
				t.Fatal("invalid worker result escaped or leaked owner", err)
			}
		})
	}
}

func TestProfileComparisonPaidPollCannotRebindEitherSourceVersion(t *testing.T) {
	for _, baseline := range []bool{false, true} {
		f, request := newComparisonServiceFixture(t)
		f.ready = false
		invocation := f.invocation("compare_profiles")
		invocation.input = ContextQueryInput{Comparison: request}
		service, _ := f.s.ProfileComparisons()
		d, err := service.Begin(t.Context(), f, invocation, request)
		if err != nil {
			t.Fatal(err)
		}
		queryID := d.Association().QueryID
		if err := d.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if baseline {
			f.a.Scope.Comparison.Baseline.Version[0]++
			f.a.Baseline.Scope.Version = f.a.Scope.Comparison.Baseline.Version
		} else {
			f.a.Scope.Version[0]++
		}
		if !f.a.Valid(f.now) {
			t.Fatal("fresh changed-version authority invalid")
		}
		f.ready = true
		poll := f.invocation("get_query_result")
		result, err := f.s.Results.GetQueryResult(t.Context(), f, poll, queryID)
		if err == nil || result != nil || f.polls != 0 || f.reads != 0 || f.starts != 1 || f.admissions != 1 {
			t.Fatal("poll rebound immutable source or acquired replacement", err)
		}
	}
}

func TestProfileComparisonMismatchFailedCloseRetainsCharge(t *testing.T) {
	f, request := newComparisonServiceFixture(t)
	f.result = value.ProjectionResult{IncompatibleProfiles: true}
	f.closeErr = value.ErrUnavailable
	invocation := f.invocation("compare_profiles")
	invocation.input = ContextQueryInput{Comparison: request}
	service, _ := f.s.ProfileComparisons()
	d, err := service.Begin(t.Context(), f, invocation, request)
	if err != nil || d == nil || d.Refusal() != ContextProjectionIncompatibleProfiles {
		t.Fatal(err)
	}
	invocation.outcome = d
	if err := d.CheckDisclosure(t.Context()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := d.Close(context.Background()); err == nil || !f.active || f.completions != 0 {
			t.Fatal("failed close released original charge", err)
		}
	}
}
