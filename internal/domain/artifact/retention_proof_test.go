package artifact

import (
	"asservat.local/asservat/internal/domain/identity"
	"testing"
	"time"
)

func TestRetentionProofBindsCompleteBoundedTargetAndSourceVersions(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	root := "11111111-1111-4111-8111-111111111111"
	cluster := "22222222-2222-4222-8222-222222222222"
	rev := identity.Revision{UID: root, Generation: 1, Digest: [32]byte{1}}
	p := RetentionProof{RootID: root, ClusterID: cluster, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod", Topology: rev, Policy: rev, Selectors: rev, SourceCount: 2, ObservedAt: now, ValidUntil: now.Add(5 * time.Second), Sources: [2]RetentionSourceVersion{{ClusterID: root, ControlNamespaceUID: "hub", Epoch: root, Hub: true, ProtectionDigest: Digest{2}, SnapshotDigest: Digest{3}, Acceptance: rev}, {ClusterID: cluster, ControlNamespaceUID: "local", Epoch: root, ProtectionDigest: Digest{4}, SnapshotDigest: Digest{5}, Acceptance: rev}}}
	if !p.Valid(now) || !p.Matches(root, cluster, "namespace", "workload", "pod") {
		t.Fatal("valid proof")
	}
	for _, test := range []struct {
		name string
		edit func(*RetentionProof)
	}{
		{"hidden-source", func(x *RetentionProof) { x.SourceCount = 1 }},
		{"missing-hub", func(x *RetentionProof) { x.Sources[0].Hub = false }},
		{"two-hubs", func(x *RetentionProof) { x.Sources[1].Hub = true }},
		{"other-local-cluster", func(x *RetentionProof) { x.Sources[1].ClusterID = root }},
		{"duplicate-source", func(x *RetentionProof) {
			x.ClusterID = root
			x.Sources[1].ClusterID = root
			x.Sources[1].ControlNamespaceUID = "hub"
		}},
		{"missing-epoch", func(x *RetentionProof) { x.Sources[0].Epoch = "" }},
		{"missing-acceptance", func(x *RetentionProof) { x.Sources[0].Acceptance = identity.Revision{} }},
		{"missing-snapshot", func(x *RetentionProof) { x.Sources[0].SnapshotDigest = Digest{} }},
		{"missing-guard", func(x *RetentionProof) { x.Sources[0].ProtectionDigest = Digest{} }},
		{"overlong-observation", func(x *RetentionProof) { x.ValidUntil = x.ValidUntil.Add(time.Nanosecond) }},
		{"future-observation", func(x *RetentionProof) { x.ObservedAt = x.ObservedAt.Add(time.Second) }},
		{"excess-sources", func(x *RetentionProof) { x.SourceCount = 3 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := p
			test.edit(&v)
			if v.Valid(now) {
				t.Fatal("invalid proof accepted")
			}
			if !p.Valid(now) {
				t.Fatal("copied proof mutated original")
			}
		})
	}
	if p.Valid(p.ValidUntil) || p.Matches(root, cluster, "namespace", "replacement", "pod") {
		t.Fatal("expiry or target substitution")
	}
	p.SourceCount = 1
	p.Sources[1] = RetentionSourceVersion{}
	if !p.Valid(now) {
		t.Fatal("explicit single source")
	}
}
