package privacy

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/privacy"
	"slices"
)

// RetentionReader supplies the complete currently protected policy intersection
// for this exact target, including the installation baseline and local ceilings.
// Mutable names, caller-selected policies and incomplete lists cannot implement it.
type RetentionReader interface {
	RetentionPolicies(context.Context, authorization.Target) (value.PolicySet, error)
}
type RetainedPolicyReader interface {
	RetainedRetentionPolicies(context.Context, authorization.Target, []artifact.RetentionRule) (value.PolicySet, error)
}
type RetentionResolver struct {
	Policies         RetentionReader
	RetainedPolicies RetainedPolicyReader
	Now              func() time.Time
}

func (r RetentionResolver) Resolve(ctx context.Context, in value.Input) (value.Resolution, error) {
	if r.Policies == nil || r.Now == nil || ctx.Err() != nil {
		return value.Resolution{}, value.ErrUnavailable
	}
	if !in.Target.Valid() {
		return value.Resolution{}, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	set, err := r.Policies.RetentionPolicies(ctx, in.Target)
	if err != nil || ctx.Err() != nil {
		return value.Resolution{}, value.ErrUnavailable
	}
	return value.Resolve(set, in, r.Now())
}

// ResolveRetained consumes original ledger facts and current parent obligations.
// Public callers cannot supply their own older/newer lifetime or classification.
func (r RetentionResolver) ResolveRetained(ctx context.Context, in value.Input, previous value.Deadlines, origins []artifact.RetentionRule) (value.RetainedResolution, error) {
	if r.RetainedPolicies == nil || r.Now == nil || ctx.Err() != nil {
		return value.RetainedResolution{}, value.ErrUnavailable
	}
	if !in.Target.Valid() || !value.ValidPolicyOrigins(origins) {
		return value.RetainedResolution{}, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	set, err := r.RetainedPolicies.RetainedRetentionPolicies(ctx, in.Target, slices.Clone(origins))
	if err != nil || ctx.Err() != nil {
		return value.RetainedResolution{}, value.ErrUnavailable
	}
	return value.ResolveRetained(set, in, previous, r.Now())
}
