package analysis

import (
	"context"
	"errors"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/identity"
)

// HTTPHeaderReadAuthorizer is the C-03 current ordinary read decision for
// one case artifact: target rights before any protected source lookup, the
// original audience, retained policy origins and effective access dates. It
// reads no evidence and fails for every artifact that is not a published
// httpHeaders extract, without distinguishing why.
type HTTPHeaderReadAuthorizer interface {
	CurrentHTTPHeaderRead(context.Context, identities.CurrentIdentity, string, string) (value.HTTPHeaderReadAuthority, error)
}

// HTTPHeaderPageReader is the C-14 regional read of the exact pinned stored
// projection under that decision. It verifies envelope and manifest, then
// rechecks the native document (httpheaders.ReadPage) and returns only the
// selected records and gap report: no native bytes, keys or other fields.
type HTTPHeaderPageReader interface {
	ReadHTTPHeaderPage(context.Context, value.HTTPHeaderReadAuthority, value.HTTPHeaderSelection) (value.HTTPHeaderPage, error)
}

// HTTPHeaderReads serves get_http_headers (ADR-282 slice 4). Both ports are
// mandatory protected composition; this component enables no tool itself.
type HTTPHeaderReads struct {
	Authority HTTPHeaderReadAuthorizer
	Pages     HTTPHeaderPageReader
	Now       func() time.Time
}

// HTTPHeaderResult is one page with the decision that admitted it. ValidUntil
// is the earliest identity, authority and evidence-access bound.
type HTTPHeaderResult struct {
	Authority  value.HTTPHeaderReadAuthority
	Page       value.HTTPHeaderPage
	ValidUntil time.Time
}

// Read authorizes, reads one rechecked page and authorizes again after the
// blocking read. A cursor is judged only after current read rights hold, so
// an invalid cursor is no existence oracle.
func (s HTTPHeaderReads) Read(ctx context.Context, current identities.CurrentIdentity, sel value.HTTPHeaderSelection) (HTTPHeaderResult, error) {
	if s.Authority == nil || s.Pages == nil || s.Now == nil || ctx == nil || ctx.Err() != nil || current == nil || !sel.Valid() {
		return HTTPHeaderResult{}, value.ErrUnavailable
	}
	initial, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !initial.Valid(s.Now()) || !slices.Contains(initial.Scopes, "evidence:read") {
		return HTTPHeaderResult{}, value.ErrUnavailable
	}
	a, err := s.Authority.CurrentHTTPHeaderRead(ctx, current, sel.CaseID, sel.ArtifactID)
	if err != nil || ctx.Err() != nil || !a.Valid(s.Now()) || a.CaseID != sel.CaseID || a.ArtifactID != sel.ArtifactID || a.Principal != initial.Principal {
		return HTTPHeaderResult{}, value.ErrUnavailable
	}
	until := identity.Earlier(identity.Earlier(initial.ValidUntil, a.ValidUntil), a.AccessUntil)
	read, cancel := context.WithDeadline(ctx, until)
	page, err := s.Pages.ReadHTTPHeaderPage(read, a, sel)
	readErr := read.Err()
	cancel()
	if errors.Is(err, value.ErrInvalidCursor) && readErr == nil {
		return HTTPHeaderResult{}, value.ErrInvalidCursor
	}
	if err != nil || readErr != nil || !page.Valid(sel) {
		return HTTPHeaderResult{}, value.ErrUnavailable
	}
	// Revocation, deny, retention or recovery during the read withholds it.
	again, err := s.Authority.CurrentHTTPHeaderRead(ctx, current, sel.CaseID, sel.ArtifactID)
	if err != nil || ctx.Err() != nil || !again.Valid(s.Now()) || !again.SameSource(a) {
		return HTTPHeaderResult{}, value.ErrUnavailable
	}
	final, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !final.Valid(s.Now()) || final.Principal != initial.Principal || !slices.Contains(final.Scopes, "evidence:read") {
		return HTTPHeaderResult{}, value.ErrUnavailable
	}
	until = identity.Earlier(identity.Earlier(identity.Earlier(until, again.ValidUntil), again.AccessUntil), final.ValidUntil)
	if !s.Now().Before(until) {
		return HTTPHeaderResult{}, value.ErrExpired
	}
	return HTTPHeaderResult{Authority: again, Page: page, ValidUntil: until}, nil
}
