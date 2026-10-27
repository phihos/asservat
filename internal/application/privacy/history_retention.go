package privacy

import (
	"context"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/privacy"
)

type CaseMetadataPolicyReader interface {
	CaseMetadataPolicies(context.Context, authorization.Target) (value.PolicySet, error)
}
type RetainedCaseMetadataPolicyReader interface {
	RetainedCaseMetadataPolicies(context.Context, authorization.Target, []artifact.RetentionRule) (value.PolicySet, error)
}

// ResolveCaseMetadata consumes the existing case-metadata policy fields through
// the same accepted source/topology/selector boundary as evidence. It cannot
// substitute evidence defaults or invent a seven-day authority on an outage.
func (r RetentionResolver) ResolveCaseMetadata(ctx context.Context, in value.Input) (value.Resolution, error) {
	in.ControlKind = "case-metadata"
	reader, ok := r.Policies.(CaseMetadataPolicyReader)
	if !ok || r.Now == nil || ctx == nil || ctx.Err() != nil {
		return value.Resolution{}, value.ErrUnavailable
	}
	set, e := reader.CaseMetadataPolicies(ctx, in.Target)
	if e != nil {
		return value.Resolution{}, e
	}
	return value.Resolve(set, in, r.Now())
}
func (r RetentionResolver) ResolveRetainedCaseMetadata(ctx context.Context, in value.Input, previous value.Deadlines, origins []artifact.RetentionRule) (value.RetainedResolution, error) {
	in.ControlKind = "case-metadata"
	reader, ok := r.RetainedPolicies.(RetainedCaseMetadataPolicyReader)
	if !ok || r.Now == nil || ctx == nil || ctx.Err() != nil || !value.ValidPolicyOrigins(origins) {
		return value.RetainedResolution{}, value.ErrUnavailable
	}
	set, e := reader.RetainedCaseMetadataPolicies(ctx, in.Target, origins)
	if e != nil {
		return value.RetainedResolution{}, e
	}
	return value.ResolveRetained(set, in, previous, r.Now())
}
