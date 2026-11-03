package analysis

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

func comparisonPlansFixture() (ContextProjectionAuthority, ContextQueryPlan, ContextQueryPlan) {
	a := comparisonAuthorityFixture()
	incident := queryPlan(a)
	baseline := queryPlan(*a.Baseline)
	baseline.AllocationID = queryOtherID
	for _, p := range []*ContextQueryPlan{&baseline, &incident} {
		p.Profile.Worker.MemoryBytes = ProfileComparisonWorkerBytes
		p.Profile.Worker.WorkerTransientBytes = ProfileComparisonWorkerBytes
	}
	return a, baseline, incident
}

func TestProfileComparisonQueryRequiresTwoOriginalAcceptedPlans(t *testing.T) {
	a, baseline, incident := comparisonPlansFixture()
	baseline.HardUntil = a.CheckedAt.Add(6 * time.Second)
	q, err := NewProfileComparisonQuery(queryTestID, queryTestID, queryTestID, a, baseline, incident, a.CheckedAt)
	if err != nil || !q.Valid() || !q.Current(a, a.CheckedAt) || q.BaselinePlan != baseline || q.Plan != incident || !q.Deadline.Equal(baseline.HardUntil) {
		t.Fatal("pair backing or original deadline changed", err)
	}
	encoded, encodeErr := json.Marshal(q)
	var decoded ContextQuery
	if encodeErr != nil || json.Unmarshal(encoded, &decoded) != nil || !decoded.Valid() || !q.Equal(decoded) {
		t.Fatal("pair query failed immutable roundtrip", encodeErr)
	}
	if _, err := NewContextQuery(queryTestID, queryTestID, queryTestID, a, incident, a.CheckedAt); err == nil {
		t.Fatal("single-source constructor underfunded comparison")
	}
	if incident.Matches(a.Scope) {
		t.Fatal("single plan matched compound scope")
	}
	for name, mutate := range map[string]func(*ContextQuery){
		"missing-baseline":     func(q *ContextQuery) { q.BaselinePlan = ContextQueryPlan{} },
		"account":              func(q *ContextQuery) { q.BaselinePlan.AccountID = queryOtherID },
		"installation":         func(q *ContextQuery) { q.BaselinePlan.InstallationID = queryOtherID },
		"acceptance":           func(q *ContextQuery) { q.BaselinePlan.AcceptanceID = queryOtherID },
		"principal":            func(q *ContextQuery) { q.BaselinePlan.Principal.Subject = "other" },
		"allocation-reuse":     func(q *ContextQuery) { q.BaselinePlan.AllocationID = q.Plan.AllocationID },
		"physical-path":        func(q *ContextQuery) { q.BaselinePlan.Profile.Path.StoreID = queryOtherID },
		"resources":            func(q *ContextQuery) { q.BaselinePlan.Profile.Worker.CPUMilli++ },
		"baseline-hard-cutoff": func(q *ContextQuery) { q.Deadline = q.BaselinePlan.HardUntil.Add(time.Microsecond) },
		"baseline-effects":     func(q *ContextQuery) { q.BaselinePlan.EffectsUntil = q.ProviderUntil.Add(-time.Microsecond) },
		"baseline-cleanup":     func(q *ContextQuery) { q.BaselinePlan.CleanupUntil = q.CleanupUntil.Add(-time.Microsecond) },
	} {
		t.Run(name, func(t *testing.T) {
			v := q
			mutate(&v)
			if v.Valid() {
				t.Fatal("invalid pair backing accepted")
			}
		})
	}
	fresh := a
	child := *a.Baseline
	fresh.Baseline = &child
	child.Environment.Path.ID = queryTestID
	if !fresh.Valid(a.CheckedAt) || q.Current(fresh, a.CheckedAt) {
		t.Fatal("baseline routing rebound")
	}
	// Every secondary instant compares by instant, while changed values remain immutable.
	equivalent := q
	for _, ts := range []*time.Time{&equivalent.BaselinePlan.ObservedAt, &equivalent.BaselinePlan.ValidUntil, &equivalent.BaselinePlan.HardUntil, &equivalent.BaselinePlan.EffectsUntil, &equivalent.BaselinePlan.CleanupUntil, &equivalent.BaselinePlan.RetireBy} {
		*ts = ts.In(time.FixedZone("same", 7200))
	}
	if !q.Equal(equivalent) {
		t.Fatal("baseline time representation changed equality")
	}
	equivalent.BaselinePlan.RetireBy = equivalent.BaselinePlan.RetireBy.Add(time.Nanosecond)
	if q.Equal(equivalent) {
		t.Fatal("baseline horizon mutation ignored")
	}
}

func TestProfileComparisonQueryCapsAccessAndRejectsStaleOrInsufficientBacking(t *testing.T) {
	a, b, i := comparisonPlansFixture()
	a.AccessUntil = a.CheckedAt.Add(5 * time.Second)
	a.Baseline.AccessUntil = a.AccessUntil
	q, err := NewProfileComparisonQuery(queryTestID, queryTestID, queryTestID, a, b, i, a.CheckedAt)
	if err != nil || !q.Deadline.Equal(a.AccessUntil) {
		t.Fatal("original source access extended", err)
	}
	for name, mutate := range map[string]func(*ContextQueryPlan){
		"expired": func(p *ContextQueryPlan) { p.ValidUntil = a.CheckedAt },
		"future":  func(p *ContextQueryPlan) { p.ObservedAt = a.CheckedAt.Add(time.Second) },
		"effects": func(p *ContextQueryPlan) { p.EffectsUntil = a.CheckedAt.Add(90 * time.Second) },
		"cleanup": func(p *ContextQueryPlan) { p.CleanupUntil = p.EffectsUntil.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := b
			mutate(&bad)
			if _, err := NewProfileComparisonQuery(queryTestID, queryTestID, queryTestID, a, bad, i, a.CheckedAt); err == nil {
				t.Fatal("insufficient secondary backing accepted")
			}
		})
	}
}

func TestProfileComparisonPlansSameWorkloadAndLegacyJSON(t *testing.T) {
	a, b, i := comparisonPlansFixture()
	s := a.Scope
	s.Comparison.Baseline.ClusterID, s.Comparison.Baseline.NamespaceUID, s.Comparison.Baseline.WorkloadUID = s.ClusterID, s.NamespaceUID, s.WorkloadUID
	b.ClusterID, b.NamespaceUID, b.WorkloadUID = i.ClusterID, i.NamespaceUID, i.WorkloadUID
	b.Profile.Path.TargetClusterID = i.ClusterID
	b.AllocationID = i.AllocationID
	if !ProfileComparisonPlansMatch(s, b, i) {
		t.Fatal("same workload pair rejected")
	}
	b.AllocationID = queryOtherID
	if ProfileComparisonPlansMatch(s, b, i) {
		t.Fatal("one workload split across two allocations")
	}
	legacy := testAuthority()
	q, err := NewContextQuery(queryTestID, queryTestID, queryTestID, legacy, queryPlan(legacy), legacy.CheckedAt)
	if err != nil {
		t.Fatal(err)
	}
	old := struct {
		ID, OperationID, WorkerID                         string
		Scope                                             ContextProjectionScope
		Plan                                              ContextQueryPlan
		RecoveryIssuerEpoch                               string
		RecoveryRevision                                  identity.Revision
		CreatedAt, Deadline, WorkerUntil, CredentialUntil time.Time
		ProviderUntil, CleanupUntil                       time.Time
	}{q.ID, q.OperationID, q.WorkerID, q.Scope, q.Plan, q.RecoveryIssuerEpoch, q.RecoveryRevision, q.CreatedAt, q.Deadline, q.WorkerUntil, q.CredentialUntil, q.ProviderUntil, q.CleanupUntil}
	got, e := json.Marshal(q)
	want, e2 := json.Marshal(old)
	if e != nil || e2 != nil || !bytes.Equal(got, want) {
		t.Fatal("legacy query bytes changed", e, e2)
	}
	q.BaselinePlan = b
	if q.Valid() {
		t.Fatal("single-source query accepted hidden baseline")
	}
}

func TestProfileComparisonSameArtifactStillRequiresPairPlan(t *testing.T) {
	a, _, incident := comparisonPlansFixture()
	s, _ := a.Scope.IncidentScope()
	a.Scope.Comparison.Baseline = ProfileComparisonBaseline{CaseID: s.CaseID, ArtifactID: s.ArtifactID, CaptureID: s.CaptureID, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID, PodUID: s.PodUID, Version: s.Version}
	baselineAuthority := a
	baselineAuthority.Scope, baselineAuthority.Baseline = s, nil
	a.Baseline = &baselineAuthority
	q, err := NewProfileComparisonQuery(queryTestID, queryTestID, queryTestID, a, incident, incident, a.CheckedAt)
	if err != nil || !q.Valid() || q.BaselinePlan != incident || q.Scope.QueryUnits() != ProfileComparisonQueryUnits {
		t.Fatal("same artifact pair lost independent plan or fixed charging", err)
	}
	q.BaselinePlan = ContextQueryPlan{}
	if q.Valid() {
		t.Fatal("same artifact comparison collapsed to one plan")
	}
}

func TestProfileComparisonPlansRequireCandidateMemoryDeclaration(t *testing.T) {
	for _, lowerPhysical := range []bool{false, true} {
		a, b, i := comparisonPlansFixture()
		for _, p := range []*ContextQueryPlan{&b, &i} {
			p.Profile.Worker.WorkerTransientBytes = ProfileSummaryWorkerBytes
			if lowerPhysical {
				p.Profile.Worker.MemoryBytes = ProfileSummaryWorkerBytes
			}
		}
		bs, _ := a.Scope.BaselineScope()
		is, _ := a.Scope.IncidentScope()
		if !b.Matches(bs) || !i.Matches(is) {
			t.Fatal("legacy summary floor changed")
		}
		if ProfileComparisonPlansMatch(a.Scope, b, i) {
			t.Fatal("legacy summary memory declaration authorized comparison")
		}
		if _, err := NewProfileComparisonQuery(queryTestID, queryTestID, queryTestID, a, b, i, a.CheckedAt); err == nil {
			t.Fatal("constructor bypassed comparison declaration")
		}
	}
}

func TestProfileComparisonInvocationKeepsExistingRequestBounds(t *testing.T) {
	a, _, _ := comparisonPlansFixture()
	call := ContextQueryCall{ID: queryTestID, RootID: a.Scope.RootID, Tool: "compare_profiles", InputFormat: "context-query-input/v1", MACVersion: "v1", InputDigest: a.DecisionDigest, PrincipalDigest: a.DecisionDigest, Principal: a.Scope.Principal, StartedAt: a.CheckedAt, Until: a.ValidUntil, WriteUntil: a.CheckedAt.Add(30 * time.Second)}
	if !call.Valid(a.CheckedAt) {
		t.Fatal("closed comparison invocation refused")
	}
	call.WriteUntil = call.WriteUntil.Add(time.Nanosecond)
	if call.Valid(a.CheckedAt) {
		t.Fatal("comparison invocation renewed original bound")
	}
}
