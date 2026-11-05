package authorization

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"slices"
	"time"
)

// PacketProjectionGrants proves one exact reviewed parent/child; it never reads
// evidence or reserves disclosure. The existing paid-batch transaction does that.
type PacketProjectionGrants interface {
	PacketProjectionGrant(context.Context, identities.CurrentIdentity, analysis.ContextProjectionScope, ContextProjectionEvidence, bool) (analysis.ContextQueryGrant, time.Time, error)
}

func (s GrantService) PacketProjectionGrant(ctx context.Context, current identities.CurrentIdentity, scope analysis.ContextProjectionScope, record ContextProjectionEvidence, materialize bool) (analysis.ContextQueryGrant, time.Time, error) {
	var zero analysis.ContextQueryGrant
	if ctx == nil || ctx.Err() != nil || !s.ready() || !scope.Valid() || scope.RootID != s.RootID || scope.NativeType != artifact.RawPCAPNGArtifact || !scope.PacketQuery.Valid() || !value.UUID(scope.RawGrantID) {
		return zero, time.Time{}, value.ErrGrantScope
	}
	i, err := s.human(ctx, current, "evidence:read", "evidence:raw")
	if err != nil || i.Principal != scope.Principal {
		return zero, time.Time{}, value.ErrGrantPrincipal
	}
	output := value.VerifiedOutput{CaptureID: record.CaptureID, ActionID: record.ActionID, ArtifactID: scope.ArtifactID, ExecutionDigest: record.ExecutionDigest, ArtifactDigest: record.Version, Target: record.Retained.Input.Target}
	if !output.Valid() {
		return zero, time.Time{}, value.ErrGrantScope
	}
	g, err := s.Store.Grant(ctx, scope.RawGrantID)
	if err != nil || g.RootID != s.RootID || ReviewDigest(g, g.Review) != g.ReviewDigest || g.Kind == value.GrantRawQuery && (!RawQueryScopeMatches(g) || g.RawQuery.CaseID != scope.CaseID) {
		return zero, time.Time{}, value.ErrGrantScope
	}
	if !sameHuman(g.Requester, i.Principal) || g.Kind == value.GrantRawQuery && (g.Requester != i.Principal || !slices.Contains(g.RawQuery.Operations, value.GrantPacketQueryOperation)) || g.Kind == value.GrantAdHocCapture && (g.ResultAccess == nil || !slices.Contains(g.ResultAccess.Operations, value.GrantPacketQueryOperation)) {
		return zero, time.Time{}, value.ErrGrantScope
	}
	if err = value.CheckMaterialize(g, output, i.Principal.ClientID, true, s.Now()); err != nil {
		return zero, time.Time{}, err
	}
	var child value.GrantChild
	if materialize {
		child, _, err = s.Materialize(ctx, g.ID, i.Principal.ClientID, output)
	} else {
		child, err = s.Store.GrantChildFor(ctx, g.ID, scope.ArtifactID, i.Principal.ClientID)
	}
	if err != nil || child.Output != output || child.ParentID != g.ID {
		return zero, time.Time{}, value.ErrGrantScope
	}
	if err = value.CheckResultUse(g, child, i, value.GrantPacketQueryOperation, s.Now()); err != nil {
		return zero, time.Time{}, err
	}
	if materialize && !value.PoolCovers(g, value.GrantUse{Operation: value.GrantPacketQueryOperation, Bytes: analysis.ContextResultBytes, Operations: 1}) {
		return zero, time.Time{}, value.ErrGrantPoolExhausted
	}
	until := g.ExpiresAt
	if err = s.finalRawQuery(ctx, current, i, until); err != nil {
		return zero, time.Time{}, err
	}
	return analysis.ContextQueryGrant{ParentID: g.ID, ChildID: child.ID}, until, nil
}

// Produced only after complete current ordinary/raw-client/retained checks,
// with no grant materialization or query attempt. It discloses no source fields.
type packetQueryApprovalRequired struct{}

func (*packetQueryApprovalRequired) Error() string                     { return "raw packet approval required" }
func (*packetQueryApprovalRequired) PacketQueryApprovalRequired() bool { return true }
