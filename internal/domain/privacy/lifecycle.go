package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"slices"
	"time"
)

// RetainedArtifact contains trusted original collection facts and the current
// monotonic overlay. No caller may supply a new classification or anchor.
type RetainedArtifact struct {
	RootID         string
	Registration   artifact.Registration
	Input          Input
	OriginPolicies []artifact.RetentionRule
	Effective      Deadlines
	Sequence       int64
}

func (r RetainedArtifact) Valid() bool {
	d := r.Effective
	o := r.Registration
	return (r.Input.ControlKind == "" || r.Input.ControlKind == "case-metadata") && authorization.UUID(r.RootID) && o.Validate() == nil && r.Sequence >= 0 && ValidPolicyOrigins(r.OriginPolicies) && r.Input.Target.Valid() && r.Input.Target.ClusterID == o.Location.ClusterID && r.Input.AnchorAt.Equal(o.AnchorAt) && r.Input.RequestedSeconds > 0 && class(r.Input.PrivacyClass) && evidenceType(r.Input.EvidenceType) && d.ValidRetained() && d.AnchorAt.Equal(o.AnchorAt) && !d.ExpiresAt.After(o.ExpiresAt) && !d.DeleteBy.After(o.DeleteBy)
}

// LifecycleDecision records only monotonic policy shortening. It cannot grant
// access, extend a hold, revive a deleted artifact or rewrite its manifest.
type LifecycleDecision struct {
	ID, RootID             string
	Location               artifact.Location
	Target                 authorization.Target
	Sequence               int64
	RegistrationDigest     artifact.Digest
	PolicyRevision         identity.Revision
	Policies               []artifact.RetentionRule
	Origins                []artifact.RetentionRule
	Previous, Effective    Deadlines
	ObservedAt, ValidUntil time.Time
}

func (r LifecycleDecision) Valid() bool {
	if !authorization.UUID(r.ID) || !authorization.UUID(r.RootID) || r.Location.Validate() != nil || !r.Target.Valid() || r.Target.ClusterID != r.Location.ClusterID || r.Sequence < 1 || r.RegistrationDigest == (artifact.Digest{}) || !r.PolicyRevision.Valid() || len(r.Policies) < 1 || len(r.Policies) > 64 || !ValidPolicyOrigins(r.Origins) || !r.Previous.ValidRetained() || !r.Effective.ValidRetained() || !r.Effective.AnchorAt.Equal(r.Previous.AnchorAt) || r.Effective.ExpiresAt.After(r.Previous.ExpiresAt) || r.Effective.DeleteBy.After(r.Previous.DeleteBy) || (r.Effective.ExpiresAt.Equal(r.Previous.ExpiresAt) && r.Effective.DeleteBy.Equal(r.Previous.DeleteBy)) || !identity.Fresh(r.ObservedAt, r.ValidUntil, r.ObservedAt, 60*time.Second) {
		return false
	}
	last := ""
	for _, p := range r.Policies {
		if !identity.Text(p.UID, 64) || p.UID <= last || p.Generation < 1 || p.Generation > 2147483647 || p.Digest == (artifact.Digest{}) {
			return false
		}
		last = p.UID
	}
	merged, err := MergePolicyOrigins(r.Origins, r.Policies)
	return err == nil && slices.Equal(merged, r.Origins)
}

// MergePolicyOrigins retains every policy relationship already recorded for
// an artifact. Only a newer valid revision can supersede a retained reference.
func MergePolicyOrigins(old, current []artifact.RetentionRule) ([]artifact.RetentionRule, error) {
	if !ValidPolicyOrigins(old) || !ValidPolicyOrigins(current) {
		return nil, ErrInvalid
	}
	refs := map[string]artifact.RetentionRule{}
	for _, r := range old {
		refs[r.UID] = r
	}
	for _, r := range current {
		p, ok := refs[r.UID]
		if ok && (r.Generation < p.Generation || (r.Generation == p.Generation && r.Digest != p.Digest)) {
			return nil, ErrUnavailable
		}
		refs[r.UID] = r
	}
	if len(refs) > 64 {
		return nil, ErrUnavailable
	}
	out := make([]artifact.RetentionRule, 0, len(refs))
	for _, r := range refs {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b artifact.RetentionRule) int {
		if a.UID < b.UID {
			return -1
		}
		if a.UID > b.UID {
			return 1
		}
		return 0
	})
	return out, nil
}
