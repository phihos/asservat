package privacy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

// RetentionPolicies reads the current EvidenceRetentionPolicy set that the
// hub worker stores from its watch (ADR-330 D12).
type RetentionPolicies interface {
	CurrentRetentionPolicies(context.Context) ([]value.ScopedPolicy, error)
}

// RetentionResolver resolves the deadlines a new artifact stores.
type RetentionResolver struct {
	Policies RetentionPolicies
	Now      func() time.Time
}

func (r RetentionResolver) Resolve(ctx context.Context, in value.Input) (value.Resolution, error) {
	return r.resolve(ctx, in, false)
}

// ResolveCaseMetadata uses the policies' case-metadata lifetimes.
func (r RetentionResolver) ResolveCaseMetadata(ctx context.Context, in value.Input) (value.Resolution, error) {
	in.ControlKind = "case-metadata"
	return r.resolve(ctx, in, true)
}

func (r RetentionResolver) resolve(ctx context.Context, in value.Input, caseMetadata bool) (value.Resolution, error) {
	if r.Policies == nil || r.Now == nil || ctx == nil || ctx.Err() != nil {
		return value.Resolution{}, value.ErrUnavailable
	}
	policies, err := r.Policies.CurrentRetentionPolicies(ctx)
	if err != nil {
		return value.Resolution{}, value.ErrUnavailable
	}
	if caseMetadata {
		for i, p := range policies {
			policies[i].Policy = value.CaseMetadataPolicy(p)
		}
	}
	set, err := value.MatchPolicies(policies, in.Target, in.Labels, func(p []value.Policy) identity.Revision {
		b, _ := json.Marshal(p)
		return identity.Revision{UID: in.Target.ClusterID, Generation: 1, Digest: sha256.Sum256(b)}
	})
	if err != nil {
		return value.Resolution{}, err
	}
	return value.Resolve(set, in, r.Now())
}
