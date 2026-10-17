package privacy

import (
	configuration "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type acceptedRetentionFixture struct {
	now                                       time.Time
	topology                                  value.PolicyTopology
	sources                                   map[string]value.AcceptedSource
	facts                                     value.SelectorFacts
	topologyCalls, sourceCalls, selectorCalls int
	mode                                      string
}

func (f *acceptedRetentionFixture) RetentionTopology(context.Context, string) (value.PolicyTopology, error) {
	f.topologyCalls++
	v := f.topology
	v.Sources = append([]value.PolicySourceRef{}, v.Sources...)
	if f.topologyCalls == 2 {
		switch f.mode {
		case "topology-revision":
			v.Revision.Generation++
		case "topology-omitted-local":
			v.Sources = v.Sources[:1]
		}
	}
	return v, nil
}
func (f *acceptedRetentionFixture) AcceptedRetentionSource(_ context.Context, root string, ref value.PolicySourceRef) (value.AcceptedSource, error) {
	f.sourceCalls++
	v, ok := f.sources[ref.ControlNamespaceUID]
	if !ok {
		return v, errors.New("missing source")
	}
	if f.sourceCalls > 2 {
		switch f.mode {
		case "source-epoch":
			v.Epoch = "33333333-3333-4333-8333-333333333333"
		case "source-revision":
			v.Acceptance.Generation++
		case "source-snapshot":
			v.Snapshot.Revision.Digest[0]++
		case "source-not-ready":
			v.Ready = false
		case "source-bound":
			v.ObservedAt = f.now
			v.FreshUntil = f.now.Add(5 * time.Second)
		}
	}
	return v, nil
}
func (f *acceptedRetentionFixture) ProtectedRetentionSelectors(_ context.Context, t authorization.Target, ns, work []string) (value.SelectorFacts, error) {
	f.selectorCalls++
	if t != f.facts.Target || !reflect.DeepEqual(ns, []string{"privacy.example.test/class"}) || len(work) != 0 {
		return value.SelectorFacts{}, errors.New("unexpected metadata request")
	}
	if f.mode == "delayed-selector" {
		f.now = f.now.Add(6 * time.Second)
	}
	if f.mode == "source-bound" {
		f.now = f.now.Add(2 * time.Second)
	}
	return f.facts, nil
}
func acceptedRetentionTest() (*acceptedRetentionFixture, AcceptedRetentionReader) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	root := "11111111-1111-4111-8111-111111111111"
	cluster := "22222222-2222-4222-8222-222222222222"
	rev := identity.Revision{UID: "topology", Generation: 1, Digest: [32]byte{1}}
	refs := []value.PolicySourceRef{{ClusterID: root, ControlNamespaceUID: "hub", Hub: true, ProtectionDigest: artifact.Digest{2}}, {ClusterID: cluster, ControlNamespaceUID: "local", ProtectionDigest: artifact.Digest{3}}}
	f := &acceptedRetentionFixture{now: now, topology: value.PolicyTopology{RootID: root, TargetClusterID: cluster, Revision: rev, Sources: refs, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, sources: map[string]value.AcceptedSource{}, facts: value.SelectorFacts{Target: authorization.Target{ClusterID: cluster, NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod"}, Revision: rev, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), NamespaceKeys: []string{"privacy.example.test/class"}, NamespaceLabels: map[string]string{"privacy.example.test/class": "sensitive"}}}
	for _, ref := range refs {
		p := value.ScopedPolicy{Name: "rule-" + ref.ControlNamespaceUID, Policy: value.Policy{Revision: identity.Revision{UID: "rule-" + ref.ControlNamespaceUID, Generation: 1, Digest: [32]byte{4}}, Baseline: ref.Hub, PurposeRef: "debugging", DefaultSeconds: 3600, MaximumSeconds: 7200, DeletionBudgetSeconds: 300}, CaseDefaultSeconds: 3600, CaseMaximumSeconds: 7200, AuditDefaultSeconds: 3600, AuditMaximumSeconds: 7200, LegalExceptions: "disabled"}
		if !ref.Hub {
			p.Scope.NamespaceLabels = map[string]string{"privacy.example.test/class": "sensitive"}
			p.Policy.MaximumSeconds = 600
		}
		f.sources[ref.ControlNamespaceUID] = value.AcceptedSource{RootID: root, Epoch: root, Acceptance: identity.Revision{UID: cluster, Generation: rev.Generation, Digest: rev.Digest}, Ready: true, ProtectionDigest: ref.ProtectionDigest, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Snapshot: value.PolicySnapshot{SourceClusterID: ref.ClusterID, ControlNamespaceUID: ref.ControlNamespaceUID, Hub: ref.Hub, Revision: rev, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Policies: []value.ScopedPolicy{p}}}
	}
	for key, v := range f.sources {
		v.Snapshot.Revision = identity.Revision{UID: v.Snapshot.ControlNamespaceUID, Generation: 1, Digest: configuration.RetentionSnapshotDigest(v.Snapshot)}
		f.sources[key] = v
	}
	return f, AcceptedRetentionReader{Topology: f, Sources: f, Selectors: f, Now: func() time.Time { return f.now }}
}
func TestAcceptedRetentionRequiresCompleteCurrentGuardedSources(t *testing.T) {
	f, r := acceptedRetentionTest()
	got, err := r.RetentionPolicies(context.Background(), f.facts.Target)
	if err != nil || !got.Complete || len(got.Policies) != 2 || !got.FreshUntil.Equal(f.topology.FreshUntil) {
		t.Fatal(got, err)
	}
	if f.sourceCalls != 4 || f.topologyCalls != 2 || f.selectorCalls != 1 {
		t.Fatal("missing end-of-read revalidation")
	}
	if !got.Proof.Valid(f.now) || got.Proof.SourceCount != 2 || got.Proof.Policy != got.Revision || got.Proof.Topology != f.topology.Revision || !got.Proof.Matches(f.topology.RootID, f.facts.Target.ClusterID, f.facts.Target.NamespaceUID, f.facts.Target.WorkloadUID, f.facts.Target.PodUID) {
		t.Fatal("missing checked source provenance", got.Proof)
	}
	for _, mode := range []string{"missing-local", "not-ready", "wrong-root", "wrong-guard", "wrong-hub", "wrong-cluster", "stale-source", "unprotected-absence", "topology-revision", "topology-omitted-local", "source-revision", "source-epoch", "source-snapshot", "source-not-ready", "delayed-selector", "source-bound"} {
		t.Run(mode, func(t *testing.T) {
			f, r := acceptedRetentionTest()
			f.mode = mode
			local := f.sources["local"]
			switch mode {
			case "missing-local":
				delete(f.sources, "local")
			case "not-ready":
				local.Ready = false
			case "wrong-root":
				local.RootID = f.topology.TargetClusterID
			case "wrong-guard":
				local.ProtectionDigest[0]++
			case "wrong-hub":
				local.Snapshot.Hub = true
			case "wrong-cluster":
				local.Snapshot.SourceClusterID = f.topology.RootID
			case "stale-source":
				local.FreshUntil = f.now
			case "unprotected-absence":
				f.facts.NamespaceKeys = nil
				f.facts.NamespaceLabels = nil
			case "source-bound":
				local.FreshUntil = f.now.Add(time.Second)
			}
			if mode != "missing-local" {
				f.sources["local"] = local
			}
			if got, err := r.RetentionPolicies(context.Background(), f.facts.Target); err == nil || got.Complete {
				t.Fatal("unqualified source became authority", got, err)
			}
		})
	}
}
func TestAcceptedRetainedReaderKeepsOriginalPoliciesAndAvoidsUnneededMetadata(t *testing.T) {
	f, r := acceptedRetentionTest()
	p := f.sources["local"].Snapshot.Policies[0].Policy
	origins := []artifact.RetentionRule{{UID: p.Revision.UID, Generation: p.Revision.Generation, Digest: artifact.Digest(p.Revision.Digest)}}
	f.facts.NamespaceLabels["privacy.example.test/class"] = "different"
	r.Selectors = nil
	got, err := r.RetainedRetentionPolicies(context.Background(), f.facts.Target, origins)
	if err != nil || len(got.Policies) != 2 || f.selectorCalls != 0 {
		t.Fatal("lost pinned applicability", got, err)
	}
	if _, err = r.RetentionPolicies(context.Background(), f.facts.Target); err == nil {
		t.Fatal("new collection skipped required selector guard")
	}
}
