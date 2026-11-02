package analysis

import (
	"context"
	"errors"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextProjectionRouteReader resolves the bounded private case locator for
// one artifact: routing facts only, no source or selection. It is never a
// protected evidence lookup; C-03 checks target rights afterwards.
type ContextProjectionRouteReader interface {
	ResolveProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error)
}

// HTTPHeaderReads admits get_http_headers (ADR-282) as an approved query of
// one page: the same audited query ledger, C-03 ReadApproved authority,
// regional worker and one-use key slots as get_file_excerpt, with the
// httpHeaders extract as source and the record window as selection. Begin
// returns the pending query handle; get_query_result serves the page. All
// ports are mandatory protected composition; this enables no tool itself.
type HTTPHeaderReads struct {
	Service ContextProjectionService
	Routes  ContextProjectionRouteReader
}

func (s HTTPHeaderReads) Begin(ctx context.Context, current identities.CurrentIdentity, invocation ContextQueryInvocation, sel value.HTTPHeaderSelection) (*ContextProjectionDelivery, error) {
	var d *ContextProjectionDelivery
	err := queryStepped("configuration", value.ErrUnavailable)
	if sel.Valid() && s.Routes != nil {
		d, err = s.Service.begin(ctx, current, invocation, "get_http_headers", ContextQueryInput{Headers: sel}, func(ctx context.Context, caller identity.Identity, recovery artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
			c, err := s.Routes.ResolveProjectionRoute(ctx, sel.CaseID, sel.ArtifactID, caller, recovery)
			if err != nil || !c.RouteValid() || c.CaseID != sel.CaseID || c.ArtifactID != sel.ArtifactID || c.Selection != (value.LineSelection{}) ||
				c.NativeType != "" || c.Headers != (value.HTTPHeaderWindow{}) {
				return value.ContextProjectionCandidate{}, errors.Join(value.ErrUnavailable, err)
			}
			c.NativeType, c.Headers = artifact.HTTPHeadersArtifact, sel.Window()
			return c, nil
		})
	}
	s.Service.Results.refused(ctx, "http-headers", err)
	return d, err
}
