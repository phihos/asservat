package presentation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
)

type pairedBridge struct {
	*bridgeFixture
	baseline value.ContextQueryPlan
}

func (f *pairedBridge) ContextComparisonPlans(context.Context, value.ContextProjectionAuthority) ([2]value.ContextQueryPlan, error) {
	return [2]value.ContextQueryPlan{f.baseline, f.p}, nil
}
func (f *pairedBridge) ResolveProjectionRoute(_ context.Context, caseID, artifactID string, _ identity.Identity, _ artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	for _, s := range []value.ContextProjectionScope{f.a.Baseline.Scope, f.a.Scope} {
		if s.CaseID == caseID && s.ArtifactID == artifactID {
			c := s.Candidate()
			c.NativeType = ""
			c.Profile = value.ProfileSummarySelection{}
			c.Comparison = value.ProfileComparisonWindow{}
			return c, nil
		}
	}
	return value.ContextProjectionCandidate{}, value.ErrUnavailable
}
func comparisonBridge(t *testing.T, same bool) (*AuditedOperations, *pairedBridge, *presentationAuditGate, *projectionAuditTarget) {
	t.Helper()
	s, f, g, p := bridgeAuditFixture(t)
	f.p.Profile.Worker.MemoryBytes, f.p.Profile.Worker.WorkerTransientBytes = value.ProfileComparisonWorkerBytes, value.ProfileComparisonWorkerBytes
	f.a.Scope.NativeType, f.a.Scope.SourceFormat, f.a.Scope.DisplayVersion = artifact.PprofArtifact, artifact.PprofFormat, value.ProfileComparisonDisplayVersion
	f.a.Scope.SourceProjectionDigest, f.a.Scope.Selection, f.a.Scope.Profile = artifact.Digest{}, value.LineSelection{}, value.ProfileSummarySelection{SampleType: "cpu", TopN: 20}
	b := f.a
	b.Scope.DisplayVersion = value.ProfileSummaryDisplayVersion
	plan := f.p
	if !same {
		id := "22222222-2222-4222-8222-222222222222"
		b.Scope.CaseID, b.Scope.ArtifactID, b.Scope.CaptureID = id, id, id
		b.Scope.WorkloadUID, b.Scope.PodUID = "baseline-workload", "baseline-pod"
		b.Environment.Location.ArtifactID = id
		b.Environment.Processing.Location = b.Environment.Location
		b.Environment.Processing.CaptureID = id
		b.Environment.Path.ID = id
		b.Retention.WorkloadUID, b.Retention.PodUID = b.Scope.WorkloadUID, b.Scope.PodUID
		b.Scope.Version = artifact.Digest{5}
		plan.WorkloadUID, plan.AllocationID, plan.Profile.Path = b.Scope.WorkloadUID, id, b.Environment.Path
	}
	f.a.Scope.Comparison = value.ProfileComparisonWindow{Normalization: "none", Baseline: value.ProfileComparisonBaseline{CaseID: b.Scope.CaseID, ArtifactID: b.Scope.ArtifactID, CaptureID: b.Scope.CaptureID, ClusterID: b.Scope.ClusterID, NamespaceUID: b.Scope.NamespaceUID, WorkloadUID: b.Scope.WorkloadUID, PodUID: b.Scope.PodUID, Version: b.Scope.Version}}
	f.a.Baseline = &b
	pair := &pairedBridge{f, plan}
	f.s.ComparisonRoutes, f.s.Plans = pair, pair
	gate := &refusalOutcomeGate{presentationAuditGate: g, acknowledged: map[string]audit.OperationOutcome{}}
	ledger := &refusalOutcomeLedger{ContextQueryLedger: f, gate: gate}
	s.audit["normal"], f.s.Results.Ledger = gate, ledger
	reads, _ := f.s.ProfileComparisons()
	adapter, e := NewContextProjectionOperations(f.s, f.s.Results)
	if e == nil {
		p.adapter, e = adapter.WithProfileComparisons(reads)
	}
	if e != nil || !f.a.Valid(f.now) {
		t.Fatal("pair fixture", e)
	}
	name := "example.work"
	facts := value.ProfileComparisonFacts{ProfileComparisonAcquisition: value.ProfileComparisonAcquisition{ProfileType: "cpu", Mode: "interval"}, Total: 10, SymbolStatus: "complete"}
	f.result = &value.ProjectionResult{Comparison: &value.ProfileComparison{SampleType: "cpu", Unit: "nanoseconds", Normalization: "none", Aggregation: "cumulative", Comparable: true, Baseline: facts, Incident: facts, BuildStatus: "unknown", SamplingStatus: "unknown", AcquisitionStatus: "same", Rows: []value.ProfileComparisonRow{{Function: &name, Baseline: 10, Incident: 10, Delta: 0}}, Limitations: []string{}}}
	return s, pair, g, p
}
func comparisonInput(f *pairedBridge) []byte {
	b, _ := json.Marshal(ProfileComparisonOperationInput{CaseID: f.a.Scope.CaseID, ArtifactID: f.a.Scope.ArtifactID, BaselineCaseID: f.a.Baseline.Scope.CaseID, BaselineArtifactID: f.a.Baseline.Scope.ArtifactID, SampleType: "cpu", Normalization: "none", TopN: 20})
	return b
}
func TestProfileComparisonPublicPendingReadyAndRetainedRefusal(t *testing.T) {
	for _, mode := range []string{"distinct", "same", "mismatch", "mismatch-close-failure", "mismatch-audit-failure"} {
		t.Run(mode, func(t *testing.T) {
			s, f, g, p := comparisonBridge(t, mode == "same")
			f.ready = false
			pending, e := s.Call(t.Context(), f, "compare_profiles", comparisonInput(f))
			if e != nil {
				t.Fatal("pending", e)
			}
			if s.contracts.ValidateOutput("compare_profiles", pending.Body) != nil || f.admissions != 1 || f.starts != 1 {
				t.Fatalf("pending %s", pending.Body)
			}
			if e = pending.Close(t.Context()); e != nil {
				t.Fatal(e)
			}
			f.ready = true
			mismatch := strings.HasPrefix(mode, "mismatch")
			if mismatch {
				f.result = &value.ProjectionResult{IncompatibleProfiles: true}
			}
			if mode == "mismatch-audit-failure" {
				g.finishFail = true
			}
			if mode == "mismatch-close-failure" {
				f.closeErr = value.ErrUnavailable
			}
			out, e := s.Call(t.Context(), f, "get_query_result", bridgePoll(f.q.ID))
			if mode == "mismatch-audit-failure" {
				if e == nil || len(out.Body) != 0 || !f.active || f.completions != 0 {
					t.Fatal("failed audit exposed mismatch or leaked joined read", e)
				}
				return
			}
			if e != nil {
				t.Fatal("result", e)
			}
			if s.contracts.ValidateOutput("get_query_result", out.Body) != nil || f.reads != 1 || f.starts != 1 || f.completions != 0 || !f.active || out.CheckDisclosure(t.Context()) != nil {
				t.Fatal("owner not retained", e)
			}
			if p.last.delivery.Association().Profile != (value.ProfileSummarySelection{}) {
				t.Fatal("mixed summary/comparison association")
			}
			if mismatch {
				if !strings.Contains(string(out.Body), `"code":"IncompatibleProfiles"`) || strings.Contains(string(out.Body), `"rows"`) || g.outcomes[len(g.outcomes)-1].Status != "denied" {
					t.Fatalf("mismatch envelope %s", out.Body)
				}
			} else {
				var got struct {
					Data struct {
						Tool   string `json:"tool_name"`
						Result struct {
							Provenance []any `json:"provenance"`
							Data       struct {
								BaselineArtifactID string `json:"baseline_artifact_id"`
								SourceVersion      string `json:"source_version"`
							} `json:"data"`
						} `json:"result"`
					} `json:"data"`
				}
				if json.Unmarshal(out.Body, &got) != nil || got.Data.Tool != "compare_profiles" || got.Data.Result.Data.BaselineArtifactID != f.a.Baseline.Scope.ArtifactID || got.Data.Result.Data.SourceVersion != hash(f.a.Scope.Version) {
					t.Fatalf("paired provenance %s", out.Body)
				}
				want := 2
				if mode == "same" {
					want = 1
				}
				if len(got.Data.Result.Provenance) != want {
					t.Fatal("duplicate or missing source refs")
				}
			}
			e = out.Close(t.Context())
			if mode == "mismatch-close-failure" {
				if e == nil || !f.active || f.completions != 0 {
					t.Fatal("unknown close refunded batch")
				}
				return
			}
			if e != nil || f.active || f.completions != 1 {
				t.Fatal("joined close failed", e)
			}
		})
	}
}
func TestProfileComparisonAuditedInputRejectsRoleOrNormalizationSubstitution(t *testing.T) {
	for _, mode := range []string{"baseline", "incident", "normalization", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			s, f, _, p := comparisonBridge(t, false)
			p.mutate = func(call *OperationCall, raw *json.RawMessage) {
				var in ProfileComparisonOperationInput
				_ = json.Unmarshal(*raw, &in)
				switch mode {
				case "baseline":
					in.BaselineArtifactID = bridgeID
				case "incident":
					in.ArtifactID = in.BaselineArtifactID
				case "normalization":
					in.Normalization = "perSecond"
				case "mixed":
					if call.queryInvocation.CheckInput(t.Context(), analysisapp.ContextQueryInput{Comparison: value.ProfileComparisonRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, BaselineCaseID: in.BaselineCaseID, BaselineArtifactID: in.BaselineArtifactID, Selection: value.ProfileComparisonSelection{SampleType: "cpu", Normalization: "none", TopN: 20}}, QueryID: bridgeID}) == nil {
						t.Fatal("mixed input accepted")
					}
					call.queryInvocation = nil
				}
				*raw, _ = json.Marshal(in)
			}
			out, e := s.Call(t.Context(), f, "compare_profiles", comparisonInput(f))
			if e == nil || len(out.Body) != 0 || f.admissions != 0 || f.starts != 0 {
				t.Fatal("unreviewed pair dispatched", e)
			}
		})
	}
}
