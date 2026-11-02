package capture

import (
	"slices"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
)

// CompositionGroupPreview is a manual packet + syscall composition reviewed
// once (ADR-276): the parent preview carries the recorder-group/v1 scope and
// each child is one single manual recording with its own identities,
// composition, retention review and exact scope.
type CompositionGroupPreview struct {
	Children []CompositionGroupChild
}

// CompositionGroupChild is one recording of a composition group.
type CompositionGroupChild struct {
	CaptureID, ArtifactID, AttemptID, OccurrenceID, AssessmentID string
	ActionID                                                     string
	Composition                                                  planning.ProfileComposition
	Retention                                                    ContextRetentionReview
	CanonicalScope                                               []byte
	ScopeDigest                                                  artifact.Digest
}

func (g *CompositionGroupPreview) Clone() *CompositionGroupPreview {
	if g == nil {
		return nil
	}
	out := &CompositionGroupPreview{Children: slices.Clone(g.Children)}
	for i := range out.Children {
		c := &out.Children[i]
		c.Composition = *c.Composition.Clone()
		c.CanonicalScope = slices.Clone(c.CanonicalScope)
		c.Retention.Policies = slices.Clone(c.Retention.Policies)
	}
	return out
}

func (g *CompositionGroupPreview) valid(p ContextPreview) bool {
	if g == nil || len(g.Children) < 2 || len(g.Children) > MaxRecordingSaveGroupChildren || p.Intent.Composition == nil || p.Intent.Snapshot != nil || len(p.CanonicalScope) == 0 || p.ScopeDigest == (artifact.Digest{}) {
		return false
	}
	ids := map[string]bool{p.CaptureID: true}
	for _, c := range g.Children {
		for _, id := range []string{c.CaptureID, c.ArtifactID, c.AttemptID, c.OccurrenceID, c.AssessmentID} {
			if !authorization.UUID(id) || ids[id] {
				return false
			}
			ids[id] = true
		}
		if !identity.Text(c.ActionID, 64) || !c.Composition.Valid() || len(c.Composition.Components) != 1 || !c.Retention.Valid() || len(c.CanonicalScope) == 0 || len(c.CanonicalScope) > 64<<10 || c.ScopeDigest == (artifact.Digest{}) {
			return false
		}
	}
	return true
}
