package authorization

import (
	"context"
	"errors"
	"slices"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ProjectionRecoveryReader is the current recovery observation the case
// locator needs; it is not a recovery decision.
type ProjectionRecoveryReader interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}

// ProjectionRouteReader resolves the bounded private case locator for one
// artifact. Its candidate carries routing facts only, no source or selection,
// and is never a protected evidence lookup.
type ProjectionRouteReader interface {
	ResolveProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (analysis.ContextProjectionCandidate, error)
}

// HTTPHeaderReadAuthority is the C-03 current ordinary read decision for a
// published httpHeaders extract (ADR-282). It reuses every
// ContextProjectionAuthority facet (ReadApproved permissions, shares,
// recorded reviews, retained policy origins, audience, environment) with the
// source pinned to the closed httpHeaders projection: data class extract,
// format http-response-headers/v1, evidence type packetCapture and the
// one-frame recording native limit. Any other artifact is refused without
// distinguishing why. The decision covers the whole document; a page is
// selected only after it.
type HTTPHeaderReadAuthority struct {
	Projection ContextProjectionAuthority
	Recovery   ProjectionRecoveryReader
	Routes     ProjectionRouteReader
}

// httpHeaderDecisionWindow is the selection bound to the document decision:
// its first page. The page actually read is chosen by the caller afterwards.
var httpHeaderDecisionWindow = analysis.HTTPHeaderWindow{Limit: analysis.HTTPHeaderPageRecords}

func (s HTTPHeaderReadAuthority) CurrentHTTPHeaderRead(ctx context.Context, current identities.CurrentIdentity, caseID, artifactID string) (analysis.HTTPHeaderReadAuthority, error) {
	var zero analysis.HTTPHeaderReadAuthority
	p := s.Projection
	if ctx == nil || ctx.Err() != nil || current == nil || s.Recovery == nil || s.Routes == nil || p.Now == nil {
		return zero, projectionRefused("configuration", analysis.ErrUnavailable, nil)
	}
	if !(analysis.HTTPHeaderSelection{CaseID: caseID, ArtifactID: artifactID, Limit: 1}).Valid() {
		return zero, projectionRefused("candidate", analysis.ErrInvalid, nil)
	}
	until := p.Now().Add(identity.EvidenceReadRequestWindow)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	i, err := current.ResolveIdentity(call)
	if err != nil || call.Err() != nil || !i.Valid(p.Now()) || !slices.Contains(i.Scopes, "evidence:read") {
		return zero, projectionRefused("identity", analysis.ErrUnavailable, errors.Join(err, call.Err()))
	}
	recovery, err := s.Recovery.RecoveryState(call)
	if err != nil || call.Err() != nil || !recovery.Valid(p.Now()) {
		return zero, projectionRefused("recovery", analysis.ErrUnavailable, errors.Join(err, call.Err()))
	}
	candidate, err := s.Routes.ResolveProjectionRoute(call, caseID, artifactID, i, recovery)
	if err != nil || call.Err() != nil || !candidate.RouteValid() || candidate.RootID != p.RootID || candidate.CaseID != caseID ||
		candidate.ArtifactID != artifactID || candidate.Principal != i.Principal || candidate.Selection != (analysis.LineSelection{}) ||
		candidate.NativeType != "" || candidate.Headers != (analysis.HTTPHeaderWindow{}) {
		return zero, projectionRefused("route", analysis.ErrUnavailable, errors.Join(err, call.Err()))
	}
	candidate.NativeType, candidate.Headers = artifact.HTTPHeadersArtifact, httpHeaderDecisionWindow
	a, err := p.ResolveProjectionCurrent(call, current, candidate)
	if err != nil {
		return zero, err
	}
	src, ok := a.Scope.Source()
	now := p.Now()
	if !ok || call.Err() != nil || !a.Valid(now) || a.Scope.Candidate() != candidate || a.Scope.NativeType != artifact.HTTPHeadersArtifact ||
		a.Environment.Recovery.IssuerEpoch != recovery.IssuerEpoch || a.Environment.Recovery.Revision != recovery.Revision || a.IdentityRevision != i.Policy {
		return zero, projectionRefused("decision", analysis.ErrUnavailable, call.Err())
	}
	out := analysis.HTTPHeaderReadAuthority{CaseID: a.Scope.CaseID, ArtifactID: a.Scope.ArtifactID, CaptureID: a.Scope.CaptureID,
		NativeType: src.NativeType, Format: src.Format, DataClass: src.DataClass, Version: a.Scope.Version, Principal: a.Scope.Principal,
		AccessUntil: a.AccessUntil, ObservedAt: a.CheckedAt, ValidUntil: identity.Earlier(a.ValidUntil, until)}
	if !out.Valid(now) {
		return zero, projectionRefused("expired", analysis.ErrExpired, nil)
	}
	return out, nil
}
