package configuration

import (
	"slices"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/configuration"
)

// ADR-247: admissionEnforced protection needs a current proof that the
// named guard protects every selector and mapping key.
func TestGuardedSourceNeedsCurrentGuardCoveringItsKeys(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	src := inheritanceSource()
	src.Protection = value.Protection{Mode: "admissionEnforced", ReviewRef: "platform-review", GuardRef: "namespace-guard"}
	src.Mapping.Field, src.Mapping.Key = "label", "owner"
	o := inheritanceObservation()
	o.Keys = value.NamespaceKeys{Labels: []string{"managed", "owner"}}
	o.Namespaces[0].Labels["owner"], o.Namespaces[0].Annotations = ValueDigest("payments"), nil
	proof := &value.NamespaceGuardProof{ClusterID: inheritanceCluster, Name: "namespace-guard", LabelKeys: []string{"managed", "owner", "team"}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	grants, reason := NamespaceGrantsWith(src, inheritanceCluster, o, value.SourceEvidence{Guard: proof, Now: now})
	if reason != "" || len(grants) != 1 {
		t.Fatalf("guarded source not granted: %q %+v", reason, grants)
	}
	for name, c := range map[string]struct {
		edit   func(*value.Source, *value.NamespaceGuardProof) *value.NamespaceGuardProof
		reason string
	}{
		"no proof": {func(*value.Source, *value.NamespaceGuardProof) *value.NamespaceGuardProof { return nil }, value.GuardUnavailable},
		"expired proof": {func(_ *value.Source, p *value.NamespaceGuardProof) *value.NamespaceGuardProof {
			p.FreshUntil = now
			return p
		}, value.GuardUnavailable},
		"other cluster": {func(_ *value.Source, p *value.NamespaceGuardProof) *value.NamespaceGuardProof {
			p.ClusterID = "x"
			return p
		}, value.GuardUnavailable},
		"other guard": {func(s *value.Source, p *value.NamespaceGuardProof) *value.NamespaceGuardProof {
			s.Protection.GuardRef = "other"
			return p
		}, value.SourceUnsupported},
		"unprotected key": {func(_ *value.Source, p *value.NamespaceGuardProof) *value.NamespaceGuardProof {
			p.LabelKeys = []string{"managed"}
			return p
		}, value.SourceUnsupported},
		"unprotected selector": {func(_ *value.Source, p *value.NamespaceGuardProof) *value.NamespaceGuardProof {
			p.LabelKeys = []string{"owner"}
			return p
		}, value.SourceUnsupported},
	} {
		t.Run(name, func(t *testing.T) {
			s, p := src, *proof
			p.LabelKeys = slices.Clone(proof.LabelKeys)
			if g, r := NamespaceGrantsWith(s, inheritanceCluster, o, value.SourceEvidence{Guard: c.edit(&s, &p), Now: now}); len(g) != 0 || r != c.reason {
				t.Fatalf("got %q %+v", r, g)
			}
		})
	}
	// An annotation mapping needs a guard that protects annotation keys.
	annotated := src
	annotated.Mapping.Field = "annotation"
	ao := inheritanceObservation()
	if g, r := NamespaceGrantsWith(annotated, inheritanceCluster, ao, value.SourceEvidence{Guard: proof, Now: now}); len(g) != 0 || r != value.SourceUnsupported {
		t.Fatalf("annotation key without annotation protection granted: %q", r)
	}
	withAnnotations := *proof
	withAnnotations.AnnotationKeys = []string{"owner"}
	if g, r := NamespaceGrantsWith(annotated, inheritanceCluster, ao, value.SourceEvidence{Guard: &withAnnotations, Now: now}); r != "" || len(g) != 1 {
		t.Fatalf("protected annotation key not granted: %q", r)
	}
}

// ADR-247: groupID mapping names the group itself; only a stable group ID of
// the configured directory (the identity settings' eligibleGroups) grants.
func TestGroupIDSourceGrantsOnlyConfiguredGroups(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	src := inheritanceSource()
	src.Mapping = value.Mapping{Field: "annotation", Key: "owner", Mode: "groupID", Issuer: "https://id.example.test"}
	o := inheritanceObservation()
	o.Namespaces[0].Annotations["owner"] = ValueDigest("8a7c1f2e-group-payments")
	dir := &value.GroupDirectory{Issuer: "https://id.example.test", Groups: []string{"8a7c1f2e-group-payments", "other-group"}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second)}
	grants, reason := NamespaceGrantsWith(src, inheritanceCluster, o, value.SourceEvidence{Directory: dir, Now: now})
	if reason != "" || len(grants) != 1 || !slices.Equal(grants[0].Subjects, []value.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "8a7c1f2e-group-payments"}}) {
		t.Fatalf("configured group not granted: %q %+v", reason, grants)
	}
	unknown := inheritanceObservation()
	unknown.Namespaces[0].Annotations["owner"] = ValueDigest("admins")
	if g, r := NamespaceGrantsWith(src, inheritanceCluster, unknown, value.SourceEvidence{Directory: dir, Now: now}); len(g) != 0 || r != "" {
		t.Fatalf("a group outside the directory was granted: %q %+v", r, g)
	}
	if g, r := NamespaceGrantsWith(src, inheritanceCluster, o, value.SourceEvidence{Now: now}); len(g) != 0 || r != value.DirectoryUnavailable {
		t.Fatalf("missing directory: %q", r)
	}
	other := *dir
	other.Issuer = "https://other.example.test"
	if g, r := NamespaceGrantsWith(src, inheritanceCluster, o, value.SourceEvidence{Directory: &other, Now: now}); len(g) != 0 || r != value.DirectoryUnavailable {
		t.Fatalf("another issuer's directory: %q", r)
	}
	if _, r := NamespaceGrants(src, inheritanceCluster, o); r != value.DirectoryUnavailable {
		t.Fatalf("evaluation without evidence: %q", r)
	}
}
