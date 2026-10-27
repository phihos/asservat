package privacy

import (
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

const previewOtherCluster = "22222222-2222-4222-8222-222222222222"

// previewFixture is one artifact bound to the hub baseline (6 h maximum, 1 h
// cleanup budget: readable until anchor+5 h, deleted by anchor+6 h) and the
// accepted hub source holding that baseline, previewed one hour after the
// anchor.
func previewFixture() (PreviewCatalog, RetainedArtifact, time.Time) {
	r, s := obligationFixture()
	s.Policies[0].Policy.Revision = identity.Revision{UID: "original", Generation: 1, Digest: artifact.Digest{1}}
	s.Policies[0].Policy.MaximumSeconds = 6 * 3600
	s.Policies[0].Policy.DeletionBudgetSeconds = 3600
	return PreviewCatalog{Sources: []PreviewSource{{Ref: PolicySourceRef{ClusterID: s.SourceClusterID, ControlNamespaceUID: "control", Hub: true}, Ready: true, Current: &s}}, Artifacts: []RetainedArtifact{r}}, r, r.Input.AnchorAt.Add(time.Hour)
}

func baselineSpec(maximum, budget int64) ScopedPolicy {
	return ScopedPolicy{Policy: Policy{Revision: identity.Revision{Digest: artifact.Digest{9}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 600, MaximumSeconds: maximum, DeletionBudgetSeconds: budget}, CaseDefaultSeconds: 3600, CaseMaximumSeconds: 7200, AuditDefaultSeconds: 3600, AuditMaximumSeconds: 7200, LegalExceptions: "disabled"}
}

func TestRetentionPreviewShorteningUsesCatchupResult(t *testing.T) {
	catalog, r, now := previewFixture()
	p, err := PreviewRetention([]RetentionChange{{Action: "update", UID: "original", Policy: baselineSpec(2*3600, 300)}}, catalog, now)
	if err != nil {
		t.Fatal(err)
	}
	// The same result the catch-up computes once the change is accepted.
	s := *catalog.Sources[0].Current
	s.Policies[0].Policy = baselineSpec(2*3600, 300).Policy
	s.Policies[0].Policy.Revision = identity.Revision{UID: "original", Generation: 2, Digest: artifact.Digest{9}}
	policies, err := HistoricalSourcePolicies(s, r)
	if err != nil {
		t.Fatal(err)
	}
	want, _, err := ApplyRetainedObligation(r, policies)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Complete() || p.Scanned != 1 || p.Affected != 1 || p.Unknown != 0 || p.ReadClosed != 0 || p.DeletionDue != 0 || !p.EarliestDeleteBy.Equal(want.DeleteBy) || !p.EarliestExpiresAt.Equal(want.ExpiresAt) || !want.DeleteBy.Equal(r.Input.AnchorAt.Add(2*time.Hour)) {
		t.Fatalf("%+v want %+v", p, want)
	}
	if len(p.Groups) != 1 || p.Groups[0].Affected != 1 || p.Groups[0].PrivacyClass != "potentialPersonalData" || p.Groups[0].EvidenceType != "context" || !p.Groups[0].EarliestDeleteBy.Equal(want.DeleteBy) {
		t.Fatalf("%+v", p.Groups)
	}
	// A maximum already past closes access now and makes deletion due.
	p, err = PreviewRetention([]RetentionChange{{Action: "update", UID: "original", Policy: baselineSpec(1800, 300)}}, catalog, now)
	if err != nil || p.Affected != 1 || p.ReadClosed != 1 || p.DeletionDue != 1 || !p.EarliestDeleteBy.Equal(r.Input.AnchorAt.Add(30*time.Minute)) {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestRetentionPreviewLengtheningNeverMovesBoundDates(t *testing.T) {
	catalog, _, now := previewFixture()
	for _, change := range []RetentionChange{
		{Action: "update", UID: "original", Policy: baselineSpec(48*3600, 300)},
		{Action: "create", Policy: func() ScopedPolicy {
			p := baselineSpec(72*3600, 300)
			p.Policy.Baseline = false
			p.Scope.ClusterIDs = []string{catalog.Sources[0].Ref.ClusterID}
			return p
		}()},
	} {
		p, err := PreviewRetention([]RetentionChange{change}, catalog, now)
		if err != nil || p.Scanned != 1 || p.Affected != 0 || p.Unknown != 0 || !p.EarliestDeleteBy.IsZero() || !p.EarliestExpiresAt.IsZero() || !p.Complete() {
			t.Fatalf("%s: %+v %v", change.Action, p, err)
		}
	}
	// Deleting the only baseline never extends a date; it is flagged because
	// it suspends new collection.
	p, err := PreviewRetention([]RetentionChange{{Action: "delete", UID: "original"}}, catalog, now)
	if err != nil || p.Affected != 0 || !p.BaselineChanged {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestRetentionPreviewUnknownSelectorHistory(t *testing.T) {
	catalog, r, now := previewFixture()
	labelled := baselineSpec(1800, 300)
	labelled.Policy.Baseline = false
	labelled.Scope.NamespaceLabels = map[string]string{"team": "payments"}
	p, err := PreviewRetention([]RetentionChange{{Action: "create", Policy: labelled}}, catalog, now)
	if err != nil || p.Scanned != 1 || p.Unknown != 1 || p.Affected != 0 || !p.EarliestDeleteBy.IsZero() || p.Groups[0].Unknown != 1 {
		t.Fatalf("new selector assumed: %+v %v", p, err)
	}
	// The same selector on a policy the artifact is already bound to follows
	// the bound UID instead of current labels.
	bound := labelled
	bound.Policy.Baseline = false
	catalog.Sources[0].Current.Policies = append(catalog.Sources[0].Current.Policies, ScopedPolicy{Name: "team", Policy: Policy{Revision: identity.Revision{UID: "team", Generation: 1, Digest: artifact.Digest{4}}, PurposeRef: "diagnostics", DefaultSeconds: 600, MaximumSeconds: 6 * 3600, DeletionBudgetSeconds: 300}, Scope: PolicyScope{NamespaceLabels: map[string]string{"team": "payments"}}, CaseDefaultSeconds: 3600, CaseMaximumSeconds: 7200, AuditDefaultSeconds: 3600, AuditMaximumSeconds: 7200, LegalExceptions: "disabled"})
	catalog.Artifacts[0].OriginPolicies = append(catalog.Artifacts[0].OriginPolicies, artifact.RetentionRule{UID: "team", Generation: 1, Digest: artifact.Digest{4}})
	p, err = PreviewRetention([]RetentionChange{{Action: "update", UID: "team", Policy: bound}}, catalog, now)
	if err != nil || p.Unknown != 0 || p.Affected != 1 || !p.EarliestDeleteBy.Equal(r.Input.AnchorAt.Add(30*time.Minute)) {
		t.Fatalf("bound policy not followed: %+v %v", p, err)
	}
	// Rows that cannot be decoded are Unknown, never assumed unaffected.
	catalog, _, _ = previewFixture()
	catalog.Unreadable = map[string]int{previewOtherCluster: 2}
	p, err = PreviewRetention([]RetentionChange{{Action: "update", UID: "original", Policy: baselineSpec(48*3600, 300)}}, catalog, now)
	if err != nil || p.Scanned != 3 || p.Unknown != 2 || len(p.Groups) != 2 {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestRetentionPreviewIncompleteSources(t *testing.T) {
	catalog, _, now := previewFixture()
	cluster := catalog.Sources[0].Ref.ClusterID
	local := baselineSpec(1800, 300)
	local.Policy.Baseline = false
	// A local source without an accepted checkpoint: the proposal still
	// applies to that cluster's artifacts, but the cluster is incomplete.
	p, err := PreviewRetention([]RetentionChange{{Action: "create", SourceClusterID: cluster, Policy: local}}, catalog, now)
	if err != nil || p.Affected != 1 || p.Complete() || len(p.Incomplete) != 1 || p.Incomplete[0] != (PreviewIncomplete{cluster, PreviewSourceUnavailable}) {
		t.Fatalf("%+v %v", p, err)
	}
	// A local source of another cluster leaves this cluster's artifacts alone.
	p, err = PreviewRetention([]RetentionChange{{Action: "create", SourceClusterID: previewOtherCluster, Policy: local}}, catalog, now)
	if err != nil || p.Affected != 0 || len(p.Incomplete) != 1 || p.Incomplete[0].ClusterID != previewOtherCluster {
		t.Fatalf("%+v %v", p, err)
	}
	// A hub source that is not ready makes every cluster incomplete.
	catalog.Sources[0].Ready = false
	p, err = PreviewRetention([]RetentionChange{{Action: "update", UID: "original", Policy: baselineSpec(2*3600, 300)}}, catalog, now)
	if err != nil || p.Affected != 1 || p.Complete() || len(p.Incomplete) != 1 || p.Incomplete[0].ClusterID != cluster {
		t.Fatalf("%+v %v", p, err)
	}
	catalog.Sources[0].Ready = true
	p, err = PreviewRetention([]RetentionChange{{Action: "update", UID: "absent", Policy: baselineSpec(2*3600, 300)}, {Action: "delete", UID: "gone"}}, catalog, now)
	if err != nil || p.Complete() || len(p.NotEvaluated) != 2 || p.NotEvaluated[0].Reason != PreviewUnknownObject || p.Affected != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	catalog.Truncated = true
	if p, err = PreviewRetention([]RetentionChange{{Action: "update", UID: "original", Policy: baselineSpec(2*3600, 300)}}, catalog, now); err != nil || p.Complete() || !p.Truncated {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestRetentionPreviewRefusals(t *testing.T) {
	catalog, _, now := previewFixture()
	many := make([]RetentionChange, MaxRetentionPreviewChanges+1)
	for i := range many {
		many[i] = RetentionChange{Action: "create", Policy: baselineSpec(3600, 300)}
	}
	if _, err := PreviewRetention(many, catalog, now); !errors.Is(err, ErrPreviewLimit) {
		t.Fatal(err)
	}
	if _, err := PreviewRetention(nil, catalog, now); !errors.Is(err, ErrPreviewLimit) {
		t.Fatal(err)
	}
	conflicting := baselineSpec(3600, 3600) // budget not below the maximum
	nonBaseline := baselineSpec(3600, 300)
	nonBaseline.Policy.Baseline = false // empty hub scope must be the baseline
	for name, changes := range map[string][]RetentionChange{
		"duplicate":        {{Action: "update", UID: "original", Policy: baselineSpec(3600, 300)}, {Action: "delete", UID: "original"}},
		"create-with-uid":  {{Action: "create", UID: "x", Policy: baselineSpec(3600, 300)}},
		"delete-with-spec": {{Action: "delete", UID: "original", Policy: baselineSpec(3600, 300)}},
		"invalid-policy":   {{Action: "update", UID: "original", Policy: conflicting}},
		"baseline-flag":    {{Action: "update", UID: "original", Policy: nonBaseline}},
		"unknown-action":   {{Action: "replace", UID: "original"}},
		"bad-cluster":      {{Action: "delete", SourceClusterID: "cluster", UID: "original"}},
	} {
		if _, err := PreviewRetention(changes, catalog, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	catalog.Sources = nil
	if _, err := PreviewRetention([]RetentionChange{{Action: "delete", UID: "original"}}, catalog, now); !errors.Is(err, ErrUnavailable) {
		t.Fatal("no hub source", err)
	}
}
