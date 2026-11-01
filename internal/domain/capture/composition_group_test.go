package capture

import (
	"fmt"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/planning"
)

// ADR-276: a composition group needs 2 to 16 one-component children with
// distinct identities, retention review and a scope; it cannot also be a
// recording save group.
func TestCompositionGroupPreviewChildren(t *testing.T) {
	retention := ContextRetentionReview{PurposeRef: "diagnostics", RequestedSeconds: 600, MaximumSeconds: 3600, DeletionBudgetSeconds: 300, Policies: []artifact.RetentionRule{{UID: "baseline", Generation: 1, Digest: artifact.Digest{4}}}}
	component := func(id string) planning.ProfileComposition {
		return planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: id, Profile: planning.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}}}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}
	}
	child := func(n int) CompositionGroupChild {
		id := func(k int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n*10+k) }
		return CompositionGroupChild{CaptureID: id(1), ArtifactID: id(2), AttemptID: id(3), OccurrenceID: id(4), AssessmentID: id(5), ActionID: "a0123456789abcdef01234567", Composition: component("net"), Retention: retention, CanonicalScope: []byte("{}"), ScopeDigest: artifact.Digest{1}}
	}
	p := ContextPreview{CaptureID: "00000000-0000-4000-8000-000000000001", Intent: ContextIntent{Composition: &planning.ProfileComposition{}}, CanonicalScope: []byte("{}"), ScopeDigest: artifact.Digest{2}}
	g := &CompositionGroupPreview{Children: []CompositionGroupChild{child(1), child(2)}}
	if !retention.Valid() || !g.valid(p) {
		t.Fatal("valid composition group refused")
	}
	dup := g.Clone()
	dup.Children[1].CaptureID = dup.Children[0].CaptureID
	one := &CompositionGroupPreview{Children: []CompositionGroupChild{child(1)}}
	if dup.valid(p) || one.valid(p) {
		t.Fatal("duplicate identities or a single child accepted")
	}
	p.Group, p.CompositionGroup = &RecordingSaveGroupPreview{}, g
	if p.Valid() {
		t.Fatal("a preview was both a save group and a composition group")
	}
}
