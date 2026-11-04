package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// comparisonIdentity preserves the existing request identity across the three
// sequential source checks. Every read still resolves current identity; the
// first groups/scopes and every earlier deadline remain binding.
type comparisonIdentity struct {
	source  identities.CurrentIdentity
	now     func() time.Time
	initial identity.Identity
	until   time.Time
}

func (s *comparisonIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	i, err := s.source.ResolveIdentity(ctx)
	i = cloneProjectionIdentity(i)
	if err != nil || ctx.Err() != nil || !i.Valid(s.now()) {
		return identity.Identity{}, analysis.ErrUnavailable
	}
	if s.until.IsZero() {
		s.initial = cloneProjectionIdentity(i)
		s.until = i.ValidUntil
	} else {
		if !sameProjectionIdentity(s.initial, i, s.now()) {
			return identity.Identity{}, analysis.ErrUnavailable
		}
		s.until = identity.Earlier(s.until, i.ValidUntil)
	}
	i.ValidUntil = identity.Earlier(i.ValidUntil, s.until)
	if !i.Valid(s.now()) {
		return identity.Identity{}, analysis.ErrUnavailable
	}
	return i, nil
}

func (s ContextProjectionAuthority) checkProfileComparison(ctx context.Context, source identities.CurrentIdentity, candidate analysis.ContextProjectionCandidate, expected *analysis.ContextProjectionScope) (analysis.ContextProjectionAuthority, error) {
	var zero analysis.ContextProjectionAuthority
	if ctx == nil || ctx.Err() != nil || source == nil || s.Now == nil {
		return zero, projectionRefused("comparison", analysis.ErrUnavailable, nil)
	}
	if !candidate.Valid() || candidate.RootID != s.RootID {
		return zero, projectionRefused("candidate", analysis.ErrInvalid, nil)
	}
	bc, bok := candidate.BaselineCandidate()
	ic, iok := candidate.IncidentCandidate()
	if !bok || !iok {
		return zero, projectionRefused("candidate", analysis.ErrInvalid, nil)
	}
	var bs, is *analysis.ContextProjectionScope
	if expected != nil {
		b, ok := expected.BaselineScope()
		i, otherOK := expected.IncidentScope()
		if !ok || !otherOK {
			return zero, projectionRefused("candidate", analysis.ErrInvalid, nil)
		}
		bs, is = &b, &i
	}
	current := &comparisonIdentity{source: source, now: s.Now}
	baseline, err := s.checkProjection(ctx, current, bc, bs)
	if err != nil {
		return zero, projectionRefused("comparison", analysis.ErrUnavailable, err)
	}
	// Later work cannot renew the first source's original authority interval.
	call, stop := context.WithDeadline(ctx, baseline.ValidUntil)
	defer stop()
	incident, err := s.checkProjection(call, current, ic, is)
	if err != nil || call.Err() != nil || !baseline.Valid(s.Now()) {
		return zero, projectionRefused("comparison", analysis.ErrUnavailable, err)
	}
	call, stopAgain := context.WithDeadline(call, identity.Earlier(baseline.ValidUntil, incident.ValidUntil))
	defer stopAgain()
	// Re-read the fixed first version after the second source's blocking work.
	// Its new proofs may shorten, but never replace, the original time bounds.
	checked, err := s.checkProjection(call, current, bc, &baseline.Scope)
	if err != nil || call.Err() != nil || !baseline.Valid(s.Now()) || !incident.Valid(s.Now()) {
		return zero, projectionRefused("comparison", analysis.ErrUnavailable, err)
	}
	checked.CheckedAt = baseline.CheckedAt
	// A recheck may inherit this same deadline as its request bound. Preserve
	// the original source cause whenever that original interval wins or ties.
	if !checked.ValidUntil.Before(baseline.ValidUntil) {
		checked.Bound = baseline.Bound
	}
	checked.ValidUntil = identity.Earlier(baseline.ValidUntil, checked.ValidUntil)
	checked.AccessUntil = identity.Earlier(baseline.AccessUntil, checked.AccessUntil)
	checked.DeleteBy = identity.Earlier(baseline.DeleteBy, checked.DeleteBy)
	pair := incident.Scope
	pair.DisplayVersion = analysis.ProfileComparisonDisplayVersion
	pair.Comparison = candidate.Comparison
	pair.Comparison.Baseline.Version = checked.Scope.Version
	if expected != nil && pair != *expected {
		return zero, projectionRefused("comparison", analysis.ErrUnavailable, nil)
	}
	out := incident
	out.Scope = pair
	out.Baseline = &checked // owned value, never borrowed from a resolver or caller
	out.CheckedAt = baseline.CheckedAt
	out.ValidUntil = identity.Earlier(checked.ValidUntil, incident.ValidUntil)
	out.AccessUntil = identity.Earlier(checked.AccessUntil, incident.AccessUntil)
	out.DeleteBy = identity.Earlier(checked.DeleteBy, incident.DeleteBy)
	// checkProjection produces closed report labels only. Original baseline
	// wins ties: later checks may inherit its interval as a request bound.
	// An earlier incident keeps its cause unless baseline recheck is stricter.
	out.Bound = "comparison/baseline/" + checked.Bound
	if incident.ValidUntil.Before(baseline.ValidUntil) && !checked.ValidUntil.Before(incident.ValidUntil) {
		out.Bound = "comparison/incident/" + incident.Bound
	}
	out.DecisionDigest = artifact.Digest{}
	// The full pair, both independent decisions and all original/shortened
	// bounds belong to one digest. Nil Baseline leaves legacy encoding unchanged.
	encoded, err := json.Marshal(struct {
		Authority        analysis.ContextProjectionAuthority
		IncidentDecision artifact.Digest
	}{out, incident.DecisionDigest})
	if err != nil {
		return zero, projectionRefused("comparison", analysis.ErrUnavailable, nil)
	}
	out.DecisionDigest = sha256.Sum256(encoded)
	if call.Err() != nil || !out.Valid(s.Now()) {
		return zero, projectionRefused("comparison", analysis.ErrUnavailable, call.Err())
	}
	return out, nil
}
