package evidence

import (
	"encoding/json"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func comparisonWorkerAuthority(t *testing.T) (value.ContextProjectionAuthority, time.Time) {
	t.Helper()
	f := newProjectionWorkerFixture(t)
	a := f.a
	a.Scope.NativeType, a.Scope.SourceFormat, a.Scope.DisplayVersion = artifact.PprofArtifact, artifact.PprofFormat, value.ProfileSummaryDisplayVersion
	a.Scope.SourceProjectionDigest = artifact.Digest{}
	a.Scope.Selection = value.LineSelection{}
	a.Scope.Profile = value.ProfileSummarySelection{SampleType: "cpu", TopN: 20}
	baseline := a
	s := baseline.Scope
	a.Scope.DisplayVersion = value.ProfileComparisonDisplayVersion
	a.Scope.Comparison = value.ProfileComparisonWindow{Normalization: value.ProfileComparisonRaw, Baseline: value.ProfileComparisonBaseline{CaseID: s.CaseID, ArtifactID: s.ArtifactID, CaptureID: s.CaptureID, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID, PodUID: s.PodUID, Version: s.Version}}
	a.Baseline = &baseline
	if !a.Valid(f.now) {
		t.Fatal("invalid synthetic comparison authority")
	}
	return a, f.now
}

func TestComparisonAuthorityMatchesDecodedOwnedBaseline(t *testing.T) {
	a, now := comparisonWorkerAuthority(t)
	a.Bound, a.Baseline.Bound = "operator-parent-diagnostic", "operator-baseline-diagnostic"
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var decoded value.ContextProjectionAuthority
	if err = json.Unmarshal(raw, &decoded); err != nil || !decoded.Valid(now) {
		t.Fatal("decoded comparison authority", err)
	}
	if decoded.Baseline == a.Baseline || !sameProjectionAuthority(a, decoded) {
		t.Fatal("same source proofs compared by pointer identity or diagnostic text")
	}
	// Observations can refresh without changing the source/permission facts;
	// existing current checks retain the read's original deadline separately.
	decoded.Baseline.CheckedAt = decoded.Baseline.CheckedAt.Add(time.Microsecond)
	decoded.Baseline.Environment.ObservedAt = decoded.Baseline.Environment.ObservedAt.Add(time.Microsecond)
	decoded.Baseline.Environment.Recovery.ObservedAt = decoded.Baseline.Environment.Recovery.ObservedAt.Add(time.Microsecond)
	decoded.Baseline.Environment.Processing.ObservedAt = decoded.Baseline.Environment.Processing.ObservedAt.Add(time.Microsecond)
	decoded.Baseline.Retention.ObservedAt = decoded.Baseline.Retention.ObservedAt.Add(time.Microsecond)
	if !decoded.Valid(now.Add(time.Microsecond)) || !sameProjectionAuthority(a, decoded) {
		t.Fatal("baseline original facts changed with observation timing")
	}
	decoded.Baseline.DecisionDigest[0] ^= 1
	if sameProjectionAuthority(a, decoded) {
		t.Fatal("different baseline decision accepted")
	}
}

func TestComparisonAuthorityEqualityRefusesMissingOrNestedBaseline(t *testing.T) {
	a, _ := comparisonWorkerAuthority(t)
	noChild := a
	noChild.Baseline = nil
	if sameProjectionAuthority(a, noChild) || sameProjectionAuthority(noChild, a) {
		t.Fatal("missing baseline accepted")
	}
	nested := a
	child := *a.Baseline
	nested.Baseline = &child
	child.Baseline = &child
	if sameProjectionAuthority(nested, nested) || sameProjectionAuthority(a, nested) {
		t.Fatal("recursive baseline authority accepted")
	}
}
