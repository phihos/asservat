package hub

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCVerifier accepts ID tokens of an issuer for one client. The user name
// and groups come from the given claims and must be the subjects that the
// clusters' RBAC knows. It also returns the issuer's endpoints for the
// browser sign-in.
func OIDCVerifier(ctx context.Context, issuer, clientID, userClaim, groupsClaim string) (func(context.Context, string) (User, error), oauth2.Endpoint, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, oauth2.Endpoint{}, err
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	return func(ctx context.Context, token string) (User, error) {
		t, err := verifier.Verify(ctx, token)
		if err != nil {
			return User{}, err
		}
		var claims map[string]any
		if err := t.Claims(&claims); err != nil {
			return User{}, err
		}
		u := User{}
		u.Name, _ = claims[userClaim].(string)
		if u.Name == "" {
			return User{}, fmt.Errorf("token has no %s claim", userClaim)
		}
		groups, _ := claims[groupsClaim].([]any)
		for _, g := range groups {
			if s, ok := g.(string); ok {
				u.Groups = append(u.Groups, s)
			}
		}
		return u, nil
	}, provider.Endpoint(), nil
}
