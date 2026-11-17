package privacy

import (
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const (
	matchCluster = "11111111-1111-4111-8111-111111111111"
	otherCluster = "22222222-2222-4222-8222-222222222222"
)

func scoped(uid string, scope PolicyScope, maximum int64, rules ...Rule) ScopedPolicy {
	return ScopedPolicy{Name: uid, Scope: scope, Policy: Policy{Revision: identity.Revision{UID: uid, Generation: 1, Digest: artifact.Digest{1}}, Baseline: scope.Empty(), PurposeRef: "diagnostics", DefaultSeconds: maximum, MaximumSeconds: maximum, DeletionBudgetSeconds: 300, Rules: rules},
		CaseDefaultSeconds: 3600, CaseMaximumSeconds: 7200, AuditDefaultSeconds: 3600, AuditMaximumSeconds: 7200, LegalExceptions: "disabled"}
}

func stubRevision([]Policy) identity.Revision {
	return identity.Revision{UID: "set", Generation: 1, Digest: artifact.Digest{9}}
}

func TestMatchPoliciesClusterScopeLabelsAndBaseline(t *testing.T) {
	target := authorization.Target{ClusterID: matchCluster, NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod"}
	base := scoped("base", PolicyScope{}, 86400)
	here := scoped("here", PolicyScope{ClusterIDs: []string{matchCluster}}, 3600)
	there := scoped("there", PolicyScope{ClusterIDs: []string{otherCluster}}, 600)
	set, err := MatchPolicies([]ScopedPolicy{there, here, base}, target, nil, stubRevision)
	if err != nil || len(set.Policies) != 2 || set.Policies[0].Revision.UID != "base" || set.Policies[1].Revision.UID != "here" || set.Revision.UID != "set" {
		t.Fatal("cluster scope", set, err)
	}
	labeled := scoped("labeled", PolicyScope{NamespaceLabels: map[string]string{"team": "a"}, WorkloadLabels: map[string]string{"tier": "web"}}, 600)
	if _, err = MatchPolicies([]ScopedPolicy{base, labeled}, target, nil, stubRevision); !errors.Is(err, ErrUnavailable) {
		t.Fatal("covering labeled policy admitted without observed labels", err)
	}
	for _, c := range []struct {
		name   string
		labels TargetLabels
		match  bool
	}{
		{"all present", TargetLabels{Namespace: map[string]string{"team": "a", "env": "prod"}, Workload: map[string]string{"tier": "web"}}, true},
		{"namespace value differs", TargetLabels{Namespace: map[string]string{"team": "b"}, Workload: map[string]string{"tier": "web"}}, false},
		{"workload key missing", TargetLabels{Namespace: map[string]string{"team": "a"}}, false},
		{"labels on the wrong object", TargetLabels{Namespace: map[string]string{"tier": "web"}, Workload: map[string]string{"team": "a"}}, false},
		{"no labels", TargetLabels{}, false},
	} {
		set, err := MatchPolicies([]ScopedPolicy{base, labeled}, target, &c.labels, stubRevision)
		if err != nil || (len(set.Policies) == 2) != c.match {
			t.Fatal(c.name, set, err)
		}
	}
	labeled.Scope.ClusterIDs = []string{otherCluster}
	if _, err = MatchPolicies([]ScopedPolicy{base, labeled}, target, nil, stubRevision); err != nil {
		t.Fatal("non-covering labeled policy refused", err)
	}
	if _, err = MatchPolicies([]ScopedPolicy{here}, target, nil, stubRevision); !errors.Is(err, ErrUnavailable) {
		t.Fatal("no baseline admitted", err)
	}
	second := scoped("base2", PolicyScope{}, 86400)
	if _, err = MatchPolicies([]ScopedPolicy{base, second}, target, nil, stubRevision); !errors.Is(err, ErrUnavailable) {
		t.Fatal("two baselines admitted", err)
	}
}

func TestEvidenceMaximumAndEffect(t *testing.T) {
	p := scoped("p", PolicyScope{ClusterIDs: []string{matchCluster}}, 86400,
		Rule{Name: "packets", EvidenceTypes: []string{"packetCapture"}, MaxAgeSeconds: 3600},
		Rule{Name: "nonpersonal", PrivacyClasses: []string{"verifiedNonPersonal"}, MaxAgeSeconds: 600},
		Rule{Name: "general", PrivacyClasses: []string{"potentialPersonalData"}, MaxAgeSeconds: 43200})
	if got := p.Policy.EvidenceMaximum("packetCapture"); got != 3600 {
		t.Fatal("type rule", got)
	}
	if got := p.Policy.EvidenceMaximum("context"); got != 43200 {
		t.Fatal("general rule or class mismatch", got)
	}
	if got := p.Policy.EvidenceMaximum("other"); got != 3600 {
		t.Fatal("other must match every type rule", got)
	}
	e := Effect(p)
	if len(e.Clusters) != 1 || e.Budget != 300 || e.Maxima[artifact.PCAPNGArtifact] != 3600 || e.Maxima[artifact.PodStatusArtifact] != 43200 || e.CaseMaximum != 7200 || len(e.Maxima) != len(artifact.NativeTypeNames()) {
		t.Fatal("effect", e)
	}
	if e = Effect(scoped("b", PolicyScope{}, 86400)); e.Clusters == nil || len(e.Clusters) != 0 {
		t.Fatal("baseline effect must cover all clusters", e)
	}
	if e = Effect(scoped("l", PolicyScope{WorkloadLabels: map[string]string{"tier": "web"}}, 600)); e.WorkloadLabels["tier"] != "web" || e.NamespaceLabels != nil {
		t.Fatal("effect must carry the label selectors", e)
	}
}

// SC-PRV-009 shape: lowering produces an effect, raising cannot shorten (the
// SQL LEAST does that), deleting produces none, unknown UIDs are reported.
func TestPlanAndSummarizePreview(t *testing.T) {
	base := scoped("base", PolicyScope{}, 86400)
	lower := scoped("", PolicyScope{}, 600)
	effects, skipped, baseline, err := PlanPreview([]RetentionChange{{Action: "update", UID: "base", Policy: lower}}, []ScopedPolicy{base})
	if err != nil || len(effects) != 1 || effects[0].Maxima[artifact.PodStatusArtifact] != 600 || len(skipped) != 0 || baseline {
		t.Fatal("lowering", effects, skipped, baseline, err)
	}
	effects, skipped, baseline, err = PlanPreview([]RetentionChange{{Action: "delete", UID: "base"}, {Action: "update", UID: "missing", Policy: lower}}, []ScopedPolicy{base})
	if err != nil || len(effects) != 0 || len(skipped) != 1 || skipped[0].Reason != PreviewUnknownObject || !baseline {
		t.Fatal("deletion", effects, skipped, baseline, err)
	}
	if _, _, _, err = PlanPreview([]RetentionChange{{Action: "update", UID: "base", Policy: lower}, {Action: "delete", UID: "base"}}, []ScopedPolicy{base}); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate UID admitted", err)
	}
	if _, _, _, err = PlanPreview(nil, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty proposal admitted", err)
	}
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	out := SummarizePreview([]PreviewRow{
		{ClusterID: matchCluster, NativeType: artifact.PodStatusArtifact, Scanned: 3, Affected: 2, ReadClosed: 1, DeletionDue: 1, EarliestExpiresAt: now, EarliestDeleteBy: now.Add(time.Minute)},
		{ClusterID: matchCluster, CaseMetadata: true, Scanned: 1},
	}, skipped, true, now)
	if out.Scanned != 4 || out.Affected != 2 || out.ReadClosed != 1 || out.DeletionDue != 1 || !out.EarliestExpiresAt.Equal(now) || len(out.Groups) != 2 || out.Groups[0].EvidenceType != "context" || out.Groups[1].EvidenceType != "other" || !out.BaselineChanged || out.Complete() {
		t.Fatal("summary", out)
	}
}

// A rejected policy refuses collection in its cluster scope only.
func TestMatchPoliciesRefusesCoveringRejectedPolicy(t *testing.T) {
	target := authorization.Target{ClusterID: matchCluster, NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod"}
	base := scoped("base", PolicyScope{}, 86400)
	rejected := ScopedPolicy{Name: "bad", Policy: Policy{Revision: identity.Revision{UID: "bad", Generation: 1, Digest: artifact.Digest{1}}}, Scope: PolicyScope{ClusterIDs: []string{otherCluster}}, Rejected: RejectedSpec}
	if !rejected.Valid() {
		t.Fatal("rejected policy invalid")
	}
	if set, err := MatchPolicies([]ScopedPolicy{base, rejected}, target, nil, stubRevision); err != nil || len(set.Policies) != 1 {
		t.Fatal("rejected policy outside the scope blocked collection", err)
	}
	rejected.Scope = PolicyScope{}
	if _, err := MatchPolicies([]ScopedPolicy{base, rejected}, target, nil, stubRevision); !errors.Is(err, ErrUnavailable) {
		t.Fatal("covering rejected policy admitted", err)
	}
}
