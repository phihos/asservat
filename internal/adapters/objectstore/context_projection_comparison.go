package objectstore

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ServeProfileComparisons installs only the fixed full-source comparison.
func (r *ContextProjectionReader) ServeProfileComparisons(f evidence.ProfileComparer) {
	if r != nil {
		r.compare = f
	}
}

func (r *NativeContextReader) ServeProfileComparisons(f evidence.ProfileComparer) {
	if r != nil {
		r.compare = f
	}
}

// ReadProjectionComparisonNative owns both authenticated opens. The comparer
// receives streams with independent final authentication, never cached summaries.
func (r *ContextProjectionReader) ReadProjectionComparisonNative(ctx context.Context, sources [2]evidence.NativeContextSource, scope query.ContextProjectionScope, keys [2]evidence.KeyOpener, until time.Time) (query.ProjectionResult, error) {
	var zero query.ProjectionResult
	if r == nil || r.store == nil || r.compare == nil || ctx == nil || ctx.Err() != nil || keys[0] == nil || keys[1] == nil {
		return zero, query.ErrUnavailable
	}
	baseline, bok := scope.BaselineScope()
	incident, iok := scope.IncidentScope()
	if !bok || !iok {
		return zero, query.ErrUnavailable
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(until) || deadline.After(time.Now().Add(identity.EvidenceReadRequestWindow)) || !time.Now().Before(deadline) {
		return zero, query.ErrUnavailable
	}
	var inputs [2]evidence.ProfileComparisonSource
	handedOff := false
	for n, childScope := range [2]query.ContextProjectionScope{baseline, incident} {
		if !sources[n].Valid(childScope.Version) || !evidence.CanonicalProjectionExpectationBound(sources[n]) {
			return zero, query.ErrUnavailable
		}
		verifier, err := NewContextVerifier(r.store, keys[n])
		if err != nil {
			return zero, query.ErrUnavailable
		}
		opened, err := verifier.openNative(ctx, ctx, sources[n].Expectation, sources[n].Copies, minDeadline(deadline, sources[n].Expectation.Registration.ExpiresAt))
		if opened != nil {
			defer func() {
				if !handedOff {
					opened.Close()
				}
			}()
		}
		if err != nil || ctx.Err() != nil {
			return zero, query.ErrUnavailable
		}
		inputs[n] = evidence.ProfileComparisonSource{Opened: opened, Source: sources[n], Scope: childScope}
	}
	handedOff = true // ReadProfileComparison owns both closes on every exit.
	comparison, err := evidence.ReadProfileComparison(ctx, inputs[0], inputs[1], scope.Comparison.Selection(scope.Profile), r.compare)
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		comparison.Clear()
		return zero, query.ErrUnavailable
	}
	if errors.Is(err, query.ErrProfileIncompatible) {
		return query.ProjectionResult{IncompatibleProfiles: true}, nil
	}
	if err != nil {
		comparison.Clear()
		return zero, query.ErrUnavailable
	}
	result := query.ProjectionResult{Comparison: &comparison}
	if !result.Valid(scope) {
		result.Clear()
		return zero, query.ErrUnavailable
	}
	return result, nil
}

// Each ordinal has its own existing three-role remote opener. Both child IDs
// are fixed by the parent batch and independently consumed by the key service.
func (r *NativeContextReader) ReadApprovedProfileComparison(ctx context.Context, sources [2]evidence.NativeContextSource, o value.NativeOperation, scope query.ContextProjectionScope, until time.Time) (query.ProjectionResult, error) {
	var zero query.ProjectionResult
	if r == nil || ctx == nil || ctx.Err() != nil || !o.CurrentValid(time.Now()) || o.Kind != value.NativeProjection || o.Reference.InstallationID != r.scope.InstallationID || !evidence.NativeComparisonSourcesMatch(sources, scope, o) {
		return zero, query.ErrUnavailable
	}
	end, ok := ctx.Deadline()
	if !ok || end.After(until) || end.After(o.Until) || !time.Now().Before(end) {
		return zero, query.ErrUnavailable
	}
	ids, err := query.ProfileComparisonKeyChildIDs(o.ParentID)
	if err != nil {
		return zero, query.ErrUnavailable
	}
	var keys [2]evidence.KeyOpener
	for n, id := range ids {
		opener, err := kms.NewRemoteOpener(r.endpoint, r.scope, id, r.client)
		if err != nil {
			return zero, query.ErrUnavailable
		}
		defer opener.Close()
		keys[n] = opener
	}
	reader, err := r.projectionReader()
	if err != nil {
		return zero, query.ErrUnavailable
	}
	return reader.ReadProjectionComparisonNative(ctx, sources, scope, keys, end)
}
