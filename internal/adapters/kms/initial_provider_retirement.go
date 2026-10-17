package kms

import (
	"context"
	"errors"
	"net/http"
	"time"

	"asservat.local/asservat/internal/contracts"
	bao "github.com/openbao/openbao/api/v2"
)

// Revoke retires only an already positively returned original credential. The
// caller must first join its original local issuers and the activation owner;
// this is provider authentication revocation, not proof that earlier Transit,
// storage or SQL operations had no effect. Retrying this exact rights reduction
// is safe; it never creates, renews, adopts or lists credentials.
func (s *InitialProviderIssuer) Revoke(ctx context.Context, purpose string, i contracts.InitialProviderIssue, parent contracts.InitialProviderParent, r contracts.InitialProviderResponse) (time.Time, error) {
	if s == nil || ctx == nil || !s.validIssue(i, parent) || i.Response == nil || *i.Response != r || !ValidProviderToken([]byte(r.Token)) || len(r.Token) > contracts.InitialProviderTokenMaxBytes || r.Accessor == "" || r.Accessor == parent.Accessor || r.IssuedAt.Before(i.StartedAt) || r.IssuedAt.After(i.Until) || r.ExpiresAt.After(i.ExpiresBefore) {
		return time.Time{}, ErrKeyService
	}
	if _, _, ok := s.purpose(purpose); !ok {
		return time.Time{}, ErrKeyService
	}
	got, until, e := s.Check(ctx, i.ExpiresBefore)
	if e != nil || !initialProviderParentEqual(parent, got) {
		return time.Time{}, ErrKeyService
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	if s.verifyRevoked(ctx, r) == nil {
		if ctx.Err() != nil || !s.now().Before(until) {
			return time.Time{}, ErrKeyService
		}
		return until, nil
	}
	if e = s.Verify(ctx, purpose, i, parent, r); e != nil {
		return time.Time{}, ErrKeyService
	}
	// A lost revocation reply is resolved only by the original accessor's explicit
	// provider rejection AND the original token's live authentication rejection.
	_, _, _ = initialProviderCall(ctx, s.client, http.MethodPost, "auth/token/revoke-accessor", map[string]string{"accessor": r.Accessor})
	if e = s.verifyRevoked(ctx, r); e != nil || ctx.Err() != nil || !s.now().Before(until) {
		return time.Time{}, ErrKeyService
	}
	return until, nil
}
func initialProviderRejection(ctx context.Context, c *bao.Client, method, path string, body any, status int, exactError string) bool {
	if ctx.Err() != nil {
		return false
	}
	request := c.NewRequest(method, "/v1/"+path)
	if body != nil && request.SetJSONBody(body) != nil {
		return false
	}
	response, e := c.RawRequestWithContext(ctx, request)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	var provider *bao.ResponseError
	if response == nil || response.StatusCode != status || !errors.As(e, &provider) || provider.StatusCode != status || provider.RawError || ctx.Err() != nil {
		return false
	}
	if exactError == "" {
		return true
	}
	if len(provider.Errors) != 1 {
		return false
	}
	if provider.Errors[0] == exactError {
		return true
	}
	// Pinned OpenBao wraps this backend error in a single go-multierror before
	// JSON serialization. Accept that exact encoding, not prefixes/substrings,
	// additional errors or arbitrary HTTP400 responses. The original child's
	// independent authentication rejection remains mandatory below.
	return method == http.MethodPost && path == "auth/token/lookup-accessor" && status == http.StatusBadRequest && exactError == "invalid accessor" && provider.Errors[0] == "1 error occurred:\n\t* invalid accessor\n\n"
}
func (s *InitialProviderIssuer) verifyRevoked(ctx context.Context, r contracts.InitialProviderResponse) error {
	if !initialProviderRejection(ctx, s.client, http.MethodPost, "auth/token/lookup-accessor", map[string]string{"accessor": r.Accessor}, http.StatusBadRequest, "invalid accessor") {
		return ErrKeyService
	}
	child, e := s.client.Clone()
	if e != nil {
		return ErrKeyService
	}
	child.SetToken(r.Token)
	if !initialProviderRejection(ctx, child, http.MethodGet, "auth/token/lookup-self", nil, http.StatusForbidden, "") {
		return ErrKeyService
	}
	return nil
}
