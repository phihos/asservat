package authorization

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

// LogProjectionGrants proves the exact reviewed parent/child without
// reading evidence or spending a page. Each paid batch reserves its own use.
type LogProjectionGrants interface {
	LogProjectionGrant(context.Context, identities.CurrentIdentity, analysis.ContextProjectionScope, ContextProjectionEvidence, bool) (analysis.ContextQueryGrant, time.Time, error)
}

func (s GrantService) LogProjectionGrant(ctx context.Context, current identities.CurrentIdentity, scope analysis.ContextProjectionScope, record ContextProjectionEvidence, materialize bool) (analysis.ContextQueryGrant, time.Time, error) {
	if ctx == nil || ctx.Err() != nil || !s.ready() || !scope.Valid() || scope.RootID != s.RootID || scope.NativeType != artifact.LogsArtifact || scope.DisplayVersion != analysis.LogQueryDisplayVersion || !value.UUID(scope.RawGrantID) {
		return analysis.ContextQueryGrant{}, time.Time{}, value.ErrGrantScope
	}
	return s.rawProjectionGrant(ctx, current, scope, record, materialize, value.GrantLogQueryOperation)
}

// Emitted only after ordinary/raw-client/retained source checks, before any
// grant materialization/query admission; the marker carries no source details.
type logQueryApprovalRequired struct{}

func (*logQueryApprovalRequired) Error() string                     { return "raw logs approval required" }
func (*logQueryApprovalRequired) RawLogQueryApprovalRequired() bool { return true }
