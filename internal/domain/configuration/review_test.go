package configuration

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func reviewFixtureSource() Source {
	return Source{Resource: Resource{Kind: "PermissionSource", UID: "exec-uid", ResourceVersion: "1", Generation: 1, SpecDigest: artifact.Digest{7}}, Enabled: true, Type: SourceKubernetesExec,
		ClusterID: "11111111-1111-4111-8111-111111111111", Role: "workload-maintainer", NamespaceSelector: map[string]string{"managed": "true"}, ExcludedNamespaces: []string{"kube-system"},
		MaxDecisionAge: 30 * time.Second, MaxNamespaces: 10, IdentityMappingRef: "company", AdmissionParity: AdmissionParity{Mode: "noAdditionalRestrictions", ReviewRef: "platform-review"}}
}

func TestReviewSourceForAcceptsOnlyQualifiedDecisionTimeForms(t *testing.T) {
	r, reason := ReviewSourceFor(reviewFixtureSource())
	if reason != "" || r.Check != ReviewPodExec || !r.Valid() {
		t.Fatalf("exec source refused: %q %+v", reason, r)
	}
	access := reviewFixtureSource()
	access.Type, access.AccessReviewCheck, access.Role = SourceKubernetesAccessReview, ReviewWorkloadPatch, "evidence-reader"
	if r, reason := ReviewSourceFor(access); reason != "" || r.Check != ReviewWorkloadPatch || !r.Valid() {
		t.Fatalf("access-review source refused: %q", reason)
	}
	for name, change := range map[string]func(*Source){
		"disabled":        func(s *Source) { s.Enabled = false },
		"deleting":        func(s *Source) { s.Resource.Deleting = true },
		"namespace type":  func(s *Source) { s.Type = "namespaceMetadata" },
		"exec other role": func(s *Source) { s.Role = "evidence-reader" },
		"exec with check": func(s *Source) { s.AccessReviewCheck = ReviewWorkloadGet },
		"qualified adapter": func(s *Source) {
			s.AdmissionParity = AdmissionParity{Mode: "qualifiedAdapter", ReviewRef: "r", AdapterRef: "a"}
		},
		"no parity":           func(s *Source) { s.AdmissionParity = AdmissionParity{} },
		"no mapping":          func(s *Source) { s.IdentityMappingRef = "" },
		"decision age > 60s":  func(s *Source) { s.MaxDecisionAge = 61 * time.Second },
		"bad cluster":         func(s *Source) { s.ClusterID = "cluster" },
		"owner role via exec": func(s *Source) { s.Role = "evidence-owner" },
	} {
		s := reviewFixtureSource()
		change(&s)
		if _, reason := ReviewSourceFor(s); reason == "" {
			t.Errorf("%s accepted", name)
		}
	}
	owner := access
	owner.Role = "evidence-owner"
	if _, reason := ReviewSourceFor(owner); reason == "" {
		t.Error("access review granted evidence-owner: SAR maintainership supplies no team ownership or sharing")
	}
}

func TestEquivalentReviewKeepsOnlyOneSpecTransitionWithSameAuthority(t *testing.T) {
	old, _ := ReviewSourceFor(reviewFixtureSource())
	same := old
	if !EquivalentReview(old, same) {
		t.Fatal("unchanged source not equivalent")
	}
	changed := reviewFixtureSource()
	changed.Resource.Generation, changed.Resource.SpecDigest = 2, artifact.Digest{8}
	changed.NamespaceSelector = map[string]string{"managed": "yes"}
	next, _ := ReviewSourceFor(changed)
	if !EquivalentReview(old, next) {
		t.Fatal("a selector edit retired assignments although every review applies it afresh")
	}
	changed.Resource.Generation = 3
	jump, _ := ReviewSourceFor(changed)
	if EquivalentReview(old, jump) {
		t.Fatal("generation jump kept assignments")
	}
	remapped := reviewFixtureSource()
	remapped.Resource.Generation, remapped.IdentityMappingRef = 2, "other"
	m, _ := ReviewSourceFor(remapped)
	if EquivalentReview(old, m) {
		t.Fatal("identity mapping change kept assignments")
	}
	rewritten := old
	rewritten.Resource.SpecDigest = artifact.Digest{9}
	if EquivalentReview(old, rewritten) {
		t.Fatal("same generation with another spec kept assignments")
	}
}

func TestReviewSourcesBoundedPerCluster(t *testing.T) {
	var sources []Source
	for _, uid := range []string{"e", "d", "c", "b", "a"} {
		s := reviewFixtureSource()
		s.Resource.UID = uid
		sources = append(sources, s)
	}
	got := ReviewSources(sources)
	if len(got) != MaxReviewSourcesPerCluster || got[0].Resource.UID != "a" || got[3].Resource.UID != "d" {
		t.Fatalf("per-cluster bound: %+v", got)
	}
	now := time.Now()
	id := "22222222-2222-4222-8222-222222222222"
	b := PermissionBatch{RootID: id, Epoch: id, RequestID: id, TrustDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, ObservedAt: now, FreshUntil: now.Add(time.Second), ReviewSources: got}
	if err := b.Validate(now); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*PermissionBatch){
		"duplicate": func(b *PermissionBatch) { b.ReviewSources = append(got, got[0]) },
		"over cluster": func(b *PermissionBatch) {
			extra := got[0]
			extra.Resource.UID = "z"
			b.ReviewSources = append(got, extra)
		},
		"unreadable list": func(b *PermissionBatch) { b.SourcesUnavailable = true },
		"tampered authority": func(b *PermissionBatch) {
			b.ReviewSources = append([]ReviewSource{}, got...)
			b.ReviewSources[0].Role = "evidence-reader"
		},
	} {
		c := b
		change(&c)
		if c.Validate(now) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
