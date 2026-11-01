package capture

import (
	"context"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// CaptureProfiles lists the capture profile versions usable for an eligible
// target (REQ-CPR-001): the embedded builtins, the organization catalog and
// the target namespace's catalog, or only catalog's. Listing grants nothing;
// a preview runs every check again.
func (s ContextInvestigation) CaptureProfiles(ctx context.Context, source identities.CurrentIdentity, targetRef targets.WorkloadRequest, catalog string) ([]compiler.ProfileDescription, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	target, until, err := s.profileTarget(ctx, source, targetRef)
	if err != nil {
		return nil, time.Time{}, err
	}
	var published []planning.CatalogProfile
	if catalog != "builtin" && s.Profiles != nil {
		if published, err = s.Profiles.ListCatalogProfiles(ctx, target, catalog); err != nil {
			return nil, time.Time{}, err
		}
	}
	return compiler.DescribeProfiles(catalog, published), until, nil
}

// CaptureProfile reads one exact profile version for an eligible target.
func (s ContextInvestigation) CaptureProfile(ctx context.Context, source identities.CurrentIdentity, targetRef targets.WorkloadRequest, ref planning.ProfileRef) (compiler.ProfileDescription, time.Time, error) {
	var zero compiler.ProfileDescription
	if !ref.Valid() {
		return zero, time.Time{}, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	target, until, err := s.profileTarget(ctx, source, targetRef)
	if err != nil {
		return zero, time.Time{}, err
	}
	var published []planning.CatalogProfile
	if ref.Catalog != "builtin" && s.Profiles != nil {
		if published, err = s.Profiles.ReadCatalogProfiles(ctx, target, []planning.ProfileRef{ref}); err != nil {
			return zero, time.Time{}, err
		}
	}
	for _, p := range compiler.DescribeProfiles(ref.Catalog, published) {
		if p.Ref == ref {
			return p, until, nil
		}
	}
	return zero, time.Time{}, value.ErrProfileNotFound
}

// profileTarget resolves targetRef for a caller currently eligible for it.
// Catalog reads are metadata: no storage, retention or capability facts.
func (s ContextInvestigation) profileTarget(ctx context.Context, source identities.CurrentIdentity, targetRef targets.WorkloadRequest) (targets.PodResolution, time.Time, error) {
	var zero targets.PodResolution
	if !s.configured() || source == nil || ctx.Err() != nil {
		return zero, time.Time{}, value.ErrUnavailable
	}
	if !targetRef.Valid() {
		return zero, time.Time{}, value.ErrInvalid
	}
	i, err := source.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return zero, time.Time{}, value.ErrDenied
	}
	target, err := s.Targets.ResolveWorkload(ctx, targetRef)
	if err != nil {
		return zero, time.Time{}, err
	}
	current := s.Eligibility.ContextEligibilityCurrent(ctx, source, target.Target())
	if !current.Eligible || current.Principal != i.Principal || current.Target != target.Target() || !current.VerifiedIdentity.Valid(s.Now()) || !s.Now().Before(current.ValidUntil) {
		return zero, time.Time{}, value.ErrDenied
	}
	until := identity.Earlier(identity.Earlier(i.ValidUntil, current.ValidUntil), target.FreshUntil)
	if ctx.Err() != nil || !s.Now().Before(until) {
		return zero, time.Time{}, value.ErrUnavailable
	}
	return target, until, nil
}
