package authorization

import (
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/live"
	"context"
	"errors"
	"fmt"
	"time"
)

type liveCatalogBatch interface {
	ReadLiveSourceRecords(context.Context, []live.SourceReference) ([]LiveSourceRecord, error)
}

// CheckSources is one authorization phase. Common environment observations are
// shared only here; current source/audience/executor facts remain source-bound.
func (s LiveSourceAuthority) CheckSources(ctx context.Context, current identities.CurrentIdentity, expected []live.Source, projection string) ([]live.Source, time.Time, error) {
	refs := make([]live.SourceReference, len(expected))
	for n, source := range expected {
		refs[n] = live.SourceReference{ID: source.ID(), Kind: source.OwnerKind, Target: source.Target}
	}
	return s.sourcePhase(ctx, current, refs, expected, projection, false)
}
func (s LiveSourceAuthority) ResolveSources(ctx context.Context, current identities.CurrentIdentity, refs []live.SourceReference, projection string) ([]live.Source, time.Time, error) {
	return s.sourcePhase(ctx, current, refs, nil, projection, true)
}
func (s LiveSourceAuthority) sourcePhase(ctx context.Context, current identities.CurrentIdentity, input []live.SourceReference, expected []live.Source, projection string, resolve bool) ([]live.Source, time.Time, error) {
	if !s.configured() || ctx == nil || ctx.Err() != nil || current == nil || len(input) < 1 || len(input) > live.MaxSources || !live.Projection(projection) {
		return nil, time.Time{}, fmt.Errorf("%w: live_batch:30", live.ErrDenied)
	}
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	i, e := current.ResolveIdentity(call)
	i = cloneProjectionIdentity(i)
	if e != nil || !i.Valid(s.Now()) {
		return nil, time.Time{}, fmt.Errorf("%w: live_batch:37", live.ErrDenied)
	}
	until := i.ValidUntil
	refs := append([]live.SourceReference(nil), input...)
	permissions := make([]value.Projection, len(refs))
	seen := map[string]bool{}
	for n, ref := range refs {
		if !value.UUID(ref.ID) || seen[ref.ID] || ref.Kind != "policy" && ref.Kind != "manualSession" {
			return nil, time.Time{}, fmt.Errorf("%w: live_batch:45", live.ErrDenied)
		}
		seen[ref.ID] = true
		if resolve {
			refs[n].Target, e = s.Catalog.LiveSourceTarget(call, ref.ID, ref.Kind)
			if e != nil {
				return nil, time.Time{}, liveBatchRefusal("live_batch:51", e)
			}
		}
		target := refs[n].Target
		if !target.Valid() || n > 0 && (target.ClusterID != refs[0].Target.ClusterID || target.NamespaceUID != refs[0].Target.NamespaceUID || target.WorkloadUID != refs[0].Target.WorkloadUID) {
			return nil, time.Time{}, fmt.Errorf("%w: live_batch:56", live.ErrDenied)
		}
		permissions[n], e = s.Permissions.Permissions(call, target)
		if e != nil {
			return nil, time.Time{}, liveBatchRefusal("live_batch:60", e)
		}
		ordinary := value.ScopeEligibility(i, permissions[n], value.ReadLiveSource, target, s.Now())
		if !ordinary.Eligible {
			return nil, time.Time{}, fmt.Errorf("%w: live_batch:64", live.ErrDenied)
		}
		until = identity.Earlier(until, ordinary.ValidUntil)
	}
	bounded, end := context.WithDeadline(call, until)
	defer end()
	var records []LiveSourceRecord
	if batch, ok := s.Catalog.(liveCatalogBatch); ok {
		records, e = batch.ReadLiveSourceRecords(bounded, refs)
	} else {
		records = make([]LiveSourceRecord, len(refs))
		for n, ref := range refs {
			records[n], e = s.Catalog.ReadLiveSourceID(bounded, ref.Target, ref.ID, ref.Kind)
			if e != nil {
				break
			}
		}
	}
	if e != nil || len(records) != len(refs) {
		if errors.Is(e, live.ErrEnded) {
			return nil, time.Time{}, fmt.Errorf("live_batch:83: %w", e)
		}
		// An unavailable catalog/status read is not an access decision.
		if e != nil && errors.Is(e, live.ErrUnavailable) && !errors.Is(e, live.ErrDenied) {
			return nil, time.Time{}, fmt.Errorf("%w: live_batch:83: %v", live.ErrUnavailable, e)
		}
		return nil, time.Time{}, fmt.Errorf("%w: live_batch:83: %v", live.ErrDenied, e)
	}
	out := make([]live.Source, len(records))
	for n, record := range records {
		ref := refs[n]
		if record.Source.Root() != s.RootID || record.Source.ID() != ref.ID || record.Source.OwnerKind != ref.Kind || record.Source.Target != ref.Target {
			return nil, time.Time{}, fmt.Errorf("%w: live_batch:89", live.ErrDenied)
		}
		want := record.Source
		if !resolve {
			want = expected[n]
		}
		var sourceUntil time.Time
		out[n], sourceUntil, e = s.checkFacts(bounded, i, permissions[n], want, projection, record, until)
		if e != nil {
			return nil, time.Time{}, e
		}
		until = identity.Earlier(until, sourceUntil)
	}
	return s.finishSources(bounded, current, i, out, projection, until)
}

// liveBatchRefusal keeps an ended source or an unavailable dependency read
// distinct from an access decision; everything else is a denial.
func liveBatchRefusal(stage string, e error) error {
	switch {
	case errors.Is(e, live.ErrEnded):
		return fmt.Errorf("%s: %w", stage, e)
	case e != nil && !errors.Is(e, live.ErrDenied) && errors.Is(e, live.ErrUnavailable):
		return fmt.Errorf("%w: %s: %v", live.ErrUnavailable, stage, e)
	}
	return fmt.Errorf("%w: %s: %v", live.ErrDenied, stage, e)
}
