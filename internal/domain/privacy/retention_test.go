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
	return PolicySet{Target: target, Revision: identity.Revision{UID: "policies", Generation: 1, Digest: [32]byte{1}}, Policies: []Policy{
		{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 72 * 3600, MaximumSeconds: 24 * 3600, DeletionBudgetSeconds: 300},
		{Revision: identity.Revision{UID: "local", Generation: 1, Digest: [32]byte{3}}, PurposeRef: "diagnostics", DefaultSeconds: 12 * 3600, MaximumSeconds: 24 * 3600, DeletionBudgetSeconds: 120, Rules: []Rule{{Name: "cores", EvidenceTypes: []string{"coreDump", "heapDump"}, PrivacyClasses: []string{"potentialPersonalData"}, MaxAgeSeconds: 6 * 3600}}},
	}}, Input{Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: "coreDump", AnchorAt: now}, now
}

func TestCaseMetadataPreservesGeneralPrivacyRestrictionIndependentlyOfEvidenceKind(t *testing.T) {
	set, input, now := fixture()
	p := ScopedPolicy{Policy: set.Policies[1], CaseDefaultSeconds: 8 * 3600, CaseMaximumSeconds: 12 * 3600}
	p.Policy.Rules = append(p.Policy.Rules, Rule{Name: "all-sensitive-control", PrivacyClasses: []string{"potentialPersonalData"}, MaxAgeSeconds: 3 * 3600})
	set.Policies[0].DefaultSeconds, set.Policies[0].MaximumSeconds = 10*3600, 12*3600
	set.Policies[1] = CaseMetadataPolicy(p)
	input.ControlKind, input.EvidenceType = "case-metadata", "other"
	got, err := Resolve(set, input, now)
	if err != nil || got.RequestedSeconds != 8*3600 || got.MaximumSeconds != 3*3600 || !got.DeleteBy.Equal(now.Add(3*time.Hour)) || !got.ExpiresAt.Equal(now.Add(3*time.Hour-300*time.Second)) {
		t.Fatal("metadata lost general privacy restriction or inherited evidence-only restriction", got, err)
	}
}

func TestRetentionIntersection(t *testing.T) {
	set, in, now := fixture()
	in.RequestedSeconds = 7 * 24 * 3600
	r, err := Resolve(set, in, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.MaximumSeconds != 21600 || r.RequestedSeconds != 604800 || r.DeletionBudgetSeconds != 300 || !r.ExpiresAt.Equal(now.Add(5*time.Hour+55*time.Minute)) || !r.DeleteBy.Equal(now.Add(6*time.Hour)) || len(r.Policies) != 2 || r.Policies[0].UID != "baseline" || !r.ValidUntil.Equal(r.ExpiresAt) {
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
}

func TestRetentionRejectsIncompleteAndAmbiguousPolicy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PolicySet, *Input, *time.Time)
		want   error
	}{
		{"missing-baseline", func(s *PolicySet, _ *Input, _ *time.Time) { s.Policies[0].Baseline = false }, ErrUnavailable},
		{"duplicate-baseline", func(s *PolicySet, _ *Input, _ *time.Time) { s.Policies[1].Baseline = true }, ErrUnavailable},
		{"wrong-target", func(s *PolicySet, _ *Input, _ *time.Time) { s.Target.WorkloadUID = "other" }, ErrUnavailable},
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
