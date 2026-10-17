package capacity

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestCapacityEnrollmentPlanCarriesCompleteImmutableCompilerInput(t *testing.T) {
	a, g, w, p, prior, n := enrollmentObservationFacts()
	o, _, e := ComposeEnrollmentObservation(a, g, w, p, prior.Recovery, "original", n)
	if e != nil {
		t.Fatal(e)
	}
	plan, pool, source, e := o.Plan.CanonicalValues()
	if e != nil || len(plan) == 0 || len(pool) == 0 || len(source) == 0 || o.PlanDigest == (artifact.Digest{}) {
		t.Fatal("compiled body unavailable")
	}
	var body enrollmentPlanValue
	var complete ProtectedPoolPlan
	if json.Unmarshal(plan, &body) != nil || json.Unmarshal(pool, &complete) != nil || body.PoolUID != complete.UID || body.PolicyUID != complete.Policies[0].UID || body.Budget != complete.Policies[0].Budget || body.AccountVersion != "original" {
		t.Fatal("small plan lost complete pool or selected policy identity")
	}
	w.Namespace.Labels["team"] = "changed"
	a.Observation.Snapshot.Policies[0].Budget.Context.Bytes++
	got, pgot, sgot, e := o.Plan.CanonicalValues()
	if e != nil || !bytes.Equal(plan, got) || !bytes.Equal(pool, pgot) || !bytes.Equal(source, sgot) || o.NamespaceLabels["team"] != "one" {
		t.Fatal("mutable source rewrote compiled observation")
	}
	plan[0] = '!'
	pool[0] = '!'
	source[0] = '!'
	got, pgot, sgot, e = o.Plan.CanonicalValues()
	if e != nil || !json.Valid(got) || !json.Valid(pgot) || !json.Valid(sgot) {
		t.Fatal("returned slice aliases frozen plan")
	}
}

func TestCapacityEnrollmentPlanRejectsChangedSelectionAndQualification(t *testing.T) {
	for _, mode := range []string{"policy-uid", "policy-generation", "policy-digest", "budget", "scope", "pool-uid", "profile", "expired-source", "empty-account-version"} {
		t.Run(mode, func(t *testing.T) {
			a, g, w, _, _, n := enrollmentObservationFacts()
			selected, e := SelectBudget(a.Observation.Snapshot, w.Namespace, g.Keys, n)
			if e != nil {
				t.Fatal(e)
			}
			version := "original"
			switch mode {
			case "policy-uid":
				selected.Policy.UID = "replacement"
			case "policy-generation":
				selected.Policy.Generation++
			case "policy-digest":
				selected.Policy.SpecDigest[0]++
			case "budget":
				selected.Budget.Context.Bytes++
			case "scope":
				selected.Scope.NamespaceLabels["team"] = "other"
			case "pool-uid":
				selected.Pool.UID = "replacement"
			case "profile":
				selected.StorageProfile = "foreign"
			case "expired-source":
				n = a.FreshUntil
			case "empty-account-version":
				version = ""
			}
			if _, e = CompileEnrollmentPlan(a, selected, version, n); e == nil {
				t.Fatal("changed or unavailable source acquired a compiler plan")
			}
		})
	}
	a, g, w, _, _, n := enrollmentObservationFacts()
	selected, e := SelectBudget(a.Observation.Snapshot, w.Namespace, g.Keys, n)
	if e != nil {
		t.Fatal(e)
	}
	first, e := CompileEnrollmentPlan(a, selected, "original", n)
	if e != nil {
		t.Fatal(e)
	}
	a.QualificationDigest[0]++
	changed, e := CompileEnrollmentPlan(a, selected, "original", n)
	if e != nil || first.Digest() == changed.Digest() {
		t.Fatal("independent qualification omitted from retained plan")
	}
}

func TestCapacityEnrollmentDigestAloneCannotReachAnEffect(t *testing.T) {
	for _, mode := range []string{"missing-body", "changed-digest", "changed-source", "foreign-root", "foreign-cluster", "foreign-installation", "wrong-account-key"} {
		t.Run(mode, func(t *testing.T) {
			n := time.Now().UTC().Truncate(time.Microsecond)
			o, _ := enrollmentFixture(n)
			s := &enrollmentStore{now: &n}
			version := "original"
			switch mode {
			case "missing-body":
				o.Plan = EnrollmentPlan{}
			case "changed-digest":
				o.PlanDigest[0]++
			case "changed-source":
				o.SourceDigest[0]++
			case "foreign-root":
				o.Key.RootID = "30000000-0000-4000-8000-000000000022"
			case "foreign-cluster":
				o.Key.ClusterID = "30000000-0000-4000-8000-000000000023"
			case "foreign-installation":
				o.Recovery.InstallationID = "30000000-0000-4000-8000-000000000024"
			case "wrong-account-key":
				version = "different"
			}
			c := EnrollmentCoordinator{Store: s, Capture: s, Accounts: enrollmentAccounts{version, artifact.Digest{4}}, Now: func() time.Time { return n }}
			if _, e := c.Reconcile(context.Background(), o); e == nil || len(s.calls) != 0 {
				t.Fatalf("unbound plan reached SQL: %v, calls %v", e, s.calls)
			}
		})
	}
}
