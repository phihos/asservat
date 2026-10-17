package privacy

import (
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func fixture() (PolicySet, Input, time.Time) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	target := authorization.Target{ClusterID: "11111111-1111-4111-8111-111111111111", NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod"}
	return PolicySet{Target: target, Revision: identity.Revision{UID: "policies", Generation: 1, Digest: [32]byte{1}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Complete: true, Policies: []Policy{
		{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 72 * 3600, MaximumSeconds: 24 * 3600, DeletionBudgetSeconds: 300},
		{Revision: identity.Revision{UID: "local", Generation: 1, Digest: [32]byte{3}}, PurposeRef: "diagnostics", DefaultSeconds: 12 * 3600, MaximumSeconds: 24 * 3600, DeletionBudgetSeconds: 120, Rules: []Rule{{Name: "cores", EvidenceTypes: []string{"coreDump", "heapDump"}, PrivacyClasses: []string{"potentialPersonalData"}, MaxAgeSeconds: 6 * 3600}}},
	}}, Input{Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: "coreDump", AnchorAt: now}, now
}

func TestRetainedPolicyShorteningPreservesAlreadyOverdueCleanup(t *testing.T) {
	set, in, now := fixture()
	in.AnchorAt = now.Add(-3 * time.Hour)
	original, err := Resolve(set, in, now)
	if err != nil {
		t.Fatal(err)
	}
	in.RequestedSeconds = original.RequestedSeconds // freeze the original selection
	set.Policies[1].Rules[0].MaxAgeSeconds = 2 * 3600
	if _, err = Resolve(set, in, now); !errors.Is(err, ErrExpired) {
		t.Fatal("expired capture admitted", err)
	}
	r, err := ResolveRetained(set, in, original.Deadlines, now)
	if err != nil || !r.DeleteBy.Equal(in.AnchorAt.Add(2*time.Hour)) || !r.ExpiresAt.Equal(r.DeleteBy.Add(-5*time.Minute)) || !r.ValidUntil.Equal(set.FreshUntil) || !r.ValidUntil.After(now) {
		t.Fatal("overdue cleanup lost", r, err)
	}
	if !r.DeleteBy.Before(now) || !r.ExpiresAt.Before(now) {
		t.Fatal("policy change restarted the evidence clock")
	}
	// Raising a maximum/default cannot resurrect this already-expired artifact.
	set.Policies[1].Rules[0].MaxAgeSeconds = 12 * 3600
	set.Policies[0].DefaultSeconds = 24 * 3600
	again, err := ResolveRetained(set, in, r.Deadlines, now)
	if err != nil || again.Deadlines != r.Deadlines {
		t.Fatal("old evidence extended", again, err)
	}
	// A request must use its retained anchor/request, never a fresh default.
	wrong := in
	wrong.AnchorAt = now
	if _, err = ResolveRetained(set, wrong, r.Deadlines, now); err == nil {
		t.Fatal("anchor reset")
	}
	wrong = in
	wrong.RequestedSeconds = 0
	if _, err = ResolveRetained(set, wrong, r.Deadlines, now); err == nil {
		t.Fatal("new default applied to retained evidence")
	}
	set.FreshUntil = now
	if _, err = ResolveRetained(set, in, r.Deadlines, now); !errors.Is(err, ErrUnavailable) {
		t.Fatal("stale policy accepted", err)
	}
}

func TestRetainedLargerDeletionBudgetUsesAlreadyBoundDeadline(t *testing.T) {
	set, in, now := fixture()
	in.AnchorAt = now.Add(-time.Hour)
	in.RequestedSeconds = 6 * 3600
	set.Policies = set.Policies[:1]
	set.Policies[0].MaximumSeconds = 2 * 3600
	set.Policies[0].DeletionBudgetSeconds = 600
	original, err := Resolve(set, in, now)
	if err != nil {
		t.Fatal(err)
	}
	// A relaxed maximum cannot move this artifact's hard deadline. Its larger
	// cleanup budget must be subtracted from that existing, earlier deadline.
	set.Policies[0].MaximumSeconds = 4 * 3600
	set.Policies[0].DeletionBudgetSeconds = 1800
	r, err := ResolveRetained(set, in, original.Deadlines, now)
	if err != nil || !r.DeleteBy.Equal(original.DeleteBy) || !r.ExpiresAt.Equal(original.DeleteBy.Add(-30*time.Minute)) {
		t.Fatal("larger cleanup budget lost against original hard deadline", r, err)
	}
	// If the new required budget consumes the entire original lifetime, close
	// the readable interval immediately without fabricating extra cleanup time.
	set.Policies[0].DeletionBudgetSeconds = 3 * 3600
	r, err = ResolveRetained(set, in, r.Deadlines, now)
	if err != nil || !r.ExpiresAt.Equal(in.AnchorAt) || !r.DeleteBy.Equal(original.DeleteBy) {
		t.Fatal("impossible readable interval not closed", r, err)
	}
	again, err := ResolveRetained(set, in, r.Deadlines, now)
	if err != nil || again.Deadlines != r.Deadlines {
		t.Fatal("closed retained interval cannot reconcile", err)
	}
}

func TestRetentionIntersection(t *testing.T) {
	set, in, now := fixture()
	in.RequestedSeconds = 7 * 24 * 3600
	r, err := Resolve(set, in, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.MaximumSeconds != 21600 || r.RequestedSeconds != 604800 || r.DeletionBudgetSeconds != 300 || !r.ExpiresAt.Equal(now.Add(5*time.Hour+55*time.Minute)) || !r.DeleteBy.Equal(now.Add(6*time.Hour)) || len(r.Policies) != 2 || r.Policies[0].UID != "baseline" || !r.ValidUntil.Equal(set.FreshUntil) {
		t.Fatalf("incorrect intersection: %+v", r)
	}
	in.RequestedSeconds = 60
	r, err = Resolve(set, in, now)
	if err != nil || !r.ExpiresAt.Equal(now.Add(time.Minute)) || !r.DeleteBy.Equal(now.Add(6*time.Minute)) {
		t.Fatalf("short request was extended: %+v %v", r, err)
	}
	in.RequestedSeconds = 0
	in.EvidenceType = "context"
	r, err = Resolve(set, in, now)
	if err != nil || r.RequestedSeconds != 12*3600 || r.MaximumSeconds != 24*3600 {
		t.Fatalf("defaults: %+v %v", r, err)
	}
}

func TestRetentionClassAndUnknownProducer(t *testing.T) {
	for _, cls := range []string{"unknown", "potentialPersonalData", "personalData", "specialCategoryPossible"} {
		for _, typ := range []string{"coreDump", "heapDump", "other"} {
			t.Run(cls+"/"+typ, func(t *testing.T) {
				set, in, now := fixture()
				in.PrivacyClass = cls
				in.EvidenceType = typ
				r, err := Resolve(set, in, now)
				if err != nil || r.MaximumSeconds != 21600 {
					t.Fatalf("generic/personal bypass: %+v %v", r, err)
				}
			})
		}
	}
	set, in, now := fixture()
	in.PrivacyClass = "verifiedNonPersonal"
	r, err := Resolve(set, in, now)
	if err != nil || r.MaximumSeconds != 86400 {
		t.Fatalf("qualified class: %+v %v", r, err)
	}
	set.Policies[1].Rules[0].PrivacyClasses = []string{"personalData"}
	in.PrivacyClass = "specialCategoryPossible"
	r, err = Resolve(set, in, now)
	if err != nil || r.MaximumSeconds != 21600 {
		t.Fatalf("special category bypass: %+v %v", r, err)
	}
	in.PrivacyClass = "potentialPersonalData"
	r, err = Resolve(set, in, now)
	if err != nil || r.MaximumSeconds != 86400 {
		t.Fatalf("rule dimensions must AND: %+v %v", r, err)
	}
}

func TestRetentionParentsAndTightening(t *testing.T) {
	set, in, now := fixture()
	in.Parents = []Deadlines{
		{AnchorAt: now.Add(-time.Hour), ExpiresAt: now.Add(20 * time.Minute), DeleteBy: now.Add(25 * time.Minute)},
		{AnchorAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(30 * time.Minute), DeleteBy: now.Add(35 * time.Minute)},
	}
	r, err := Resolve(set, in, now)
	if err != nil || !r.AnchorAt.Equal(now.Add(-2*time.Hour)) || !r.ExpiresAt.Equal(now.Add(20*time.Minute)) || !r.DeleteBy.Equal(now.Add(25*time.Minute)) {
		t.Fatalf("parent bounds: %+v %v", r, err)
	}
	in.Parents[0].ExpiresAt = now
	if _, err = Resolve(set, in, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired parent accepted: %v", err)
	}
	later := Deadlines{AnchorAt: now, ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}
	d, err := Tighten(in.Parents[0], later)
	if err != nil || !d.ExpiresAt.Equal(now) || !d.DeleteBy.Equal(in.Parents[0].DeleteBy) || !d.AnchorAt.Equal(in.Parents[0].AnchorAt) {
		t.Fatalf("increase resurrected evidence: %+v %v", d, err)
	}
}

func TestRetentionRejectsIncompleteAndAmbiguousPolicy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PolicySet, *Input, *time.Time)
		want   error
	}{
		{"missing-baseline", func(s *PolicySet, _ *Input, _ *time.Time) { s.Policies[0].Baseline = false }, ErrUnavailable},
		{"duplicate-baseline", func(s *PolicySet, _ *Input, _ *time.Time) { s.Policies[1].Baseline = true }, ErrUnavailable},
		{"incomplete", func(s *PolicySet, _ *Input, _ *time.Time) { s.Complete = false }, ErrUnavailable},
		{"wrong-target", func(s *PolicySet, _ *Input, _ *time.Time) { s.Target.WorkloadUID = "other" }, ErrUnavailable},
		{"stale", func(s *PolicySet, _ *Input, n *time.Time) { *n = s.FreshUntil }, ErrUnavailable},
		{"clock-rollback", func(s *PolicySet, _ *Input, _ *time.Time) { s.ObservedAt = s.ObservedAt.Add(time.Second) }, ErrUnavailable},
		{"overlong-snapshot", func(s *PolicySet, _ *Input, _ *time.Time) { s.FreshUntil = s.ObservedAt.Add(61 * time.Second) }, ErrUnavailable},
		{"overflow", func(s *PolicySet, _ *Input, _ *time.Time) { s.Policies = make([]Policy, 65) }, ErrUnavailable},
		{"duplicate-source", func(s *PolicySet, _ *Input, _ *time.Time) { s.Policies[1].Revision.UID = s.Policies[0].Revision.UID }, ErrUnavailable},
		{"duplicate-rule", func(s *PolicySet, _ *Input, _ *time.Time) {
			s.Policies[1].Rules = append(s.Policies[1].Rules, s.Policies[1].Rules[0])
		}, ErrUnavailable},
		{"duplicate-type", func(s *PolicySet, _ *Input, _ *time.Time) {
			s.Policies[1].Rules[0].EvidenceTypes = []string{"coreDump", "coreDump"}
		}, ErrUnavailable},
		{"invalid-class-rule", func(s *PolicySet, _ *Input, _ *time.Time) {
			s.Policies[1].Rules[0].PrivacyClasses = []string{"anonymous"}
		}, ErrUnavailable},
		{"purpose-conflict", func(s *PolicySet, _ *Input, _ *time.Time) { s.Policies[1].PurposeRef = "different" }, ErrConflict},
		{"budget-intersection", func(s *PolicySet, _ *Input, _ *time.Time) { s.Policies[1].Rules[0].MaxAgeSeconds = 180 }, ErrConflict},
		{"invalid-budget", func(s *PolicySet, _ *Input, _ *time.Time) { s.Policies[0].DeletionBudgetSeconds = 86401 }, ErrUnavailable},
		{"invalid-time", func(_ *PolicySet, i *Input, _ *time.Time) { i.AnchorAt = i.AnchorAt.Add(-time.Nanosecond) }, ErrInvalid},
		{"future-anchor", func(_ *PolicySet, i *Input, _ *time.Time) { i.AnchorAt = i.AnchorAt.Add(time.Second) }, ErrInvalid},
		{"expired-acquisition", func(_ *PolicySet, i *Input, _ *time.Time) { i.AnchorAt = i.AnchorAt.Add(-7 * time.Hour) }, ErrExpired},
		{"negative-request", func(_ *PolicySet, i *Input, _ *time.Time) { i.RequestedSeconds = -1 }, ErrInvalid},
		{"long-request", func(_ *PolicySet, i *Input, _ *time.Time) { i.RequestedSeconds = MaxAgeSeconds + 1 }, ErrInvalid},
		{"unqualified-class", func(_ *PolicySet, i *Input, _ *time.Time) { i.PrivacyClass = "anonymous" }, ErrInvalid},
		{"missing-parent", func(_ *PolicySet, i *Input, _ *time.Time) { i.Parents = []Deadlines{{}} }, ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, i, n := fixture()
			test.mutate(&s, &i, &n)
			if _, err := Resolve(s, i, n); !errors.Is(err, test.want) {
				t.Fatalf("got %v want %v", err, test.want)
			}
		})
	}
}
