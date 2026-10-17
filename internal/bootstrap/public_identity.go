package bootstrap

import (
	"context"
	"encoding/pem"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/oidc"
	"asservat.local/asservat/internal/adapters/postgres"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/browser"
	"asservat.local/asservat/internal/transport/mcp"
)

// publicIdentityScopes are the browser login scopes; the operations require
// evidence:read, evidence:download and evidence:capture individually.
var publicIdentityScopes = []string{"openid", "evidence:read", "evidence:download", "evidence:capture"}

// publicIdentity is the ADR-180 identity layer: browser sessions and the two
// bearer resolvers, each pinned to its own audience.
type publicIdentity struct {
	settings      identity.BrowserSettings
	sessions      *identities.BrowserSessions
	mcp, download identities.Service
}

func pemRoots(der [][]byte) []byte {
	var out []byte
	for _, b := range der {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	return out
}

// newPublicIdentity reads the pinned browser settings once: issuer, client,
// origin and session epoch are fixed for this process (ADR-061); a settings
// change takes effect through a new process. Each returned closer must run
// after every user of the identity layer has joined.
// files is the public root; providers, in the installed layout, replace the
// session token files (ADR-182).
func newPublicIdentity(ctx context.Context, in *ownerInputs, files *providerInputs, providers *kms.InstalledOwnerProviderEffects, observer *kube.PermissionClient, pools *publicPools) (*publicIdentity, []func(), error) {
	var closers []func()
	fail := func(e error) (*publicIdentity, []func(), error) {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
		return nil, nil, e
	}
	p := in.config.Public
	if ctx == nil || ctx.Err() != nil || p == nil || observer == nil || pools == nil {
		return fail(mounts.ErrUnavailable)
	}
	reader, e := kube.NewBrowserSettingsClient(observer, p.BrowserSettings.Name, p.BrowserSettings.UID, p.BrowserRootID)
	if e != nil {
		return fail(mounts.ErrUnavailable)
	}
	settings, e := reader.BrowserSettings(ctx)
	if e != nil || settings.Suspended || settings.Origin != p.Origin || !settings.Valid(time.Now()) {
		return fail(mounts.ErrUnavailable)
	}
	policies, e := kube.NewIdentityPolicyClient(observer, p.IdentitySettings.Name, p.IdentitySettings.UID, settings.Issuer)
	if e != nil {
		return fail(mounts.ErrUnavailable)
	}
	secret, e := mounts.Read(ctx, files.files, contracts.OwnerPublicClientSecretFile, 4096)
	if e != nil {
		return fail(mounts.ErrUnavailable)
	}
	clientSecret := strings.TrimSpace(string(secret))
	clear(secret)
	// The Keycloak profile (ADR-053) fixes these issuer-relative endpoints.
	issuer := strings.TrimSuffix(settings.Issuer, "/")
	trust := func(audience string) oidc.Trust {
		return oidc.Trust{Issuer: settings.Issuer, Audience: audience, JWKSURL: issuer + "/protocol/openid-connect/certs", Profile: oidc.Keycloak, RootCA: pemRoots(p.ProviderRoots), KeyMaxAge: time.Minute}
	}
	provider, e := oidc.NewBrowser(oidc.BrowserTrust{Access: trust(p.BrowserAudience), ClientID: settings.ClientID, ClientSecret: clientSecret, AuthorizationEndpoint: issuer + "/protocol/openid-connect/auth", TokenEndpoint: issuer + "/protocol/openid-connect/token", RedirectURI: p.Origin + "/auth/callback", Scopes: publicIdentityScopes}, time.Now)
	if e != nil {
		return fail(mounts.ErrUnavailable)
	}
	closers = append(closers, provider.Close)
	verifier := func(audience string) (*oidc.Verifier, error) {
		v, e := oidc.New(trust(audience), time.Now)
		if e == nil {
			closers = append(closers, v.Close)
		}
		return v, e
	}
	browserTokens, e := verifier(p.BrowserAudience)
	if e != nil {
		return fail(mounts.ErrUnavailable)
	}
	mcpTokens, e := verifier(mcp.Config{PublicOrigin: p.Origin}.Resource())
	if e != nil {
		return fail(mounts.ErrUnavailable)
	}
	downloadTokens, e := verifier(browser.DownloadContentConfig{PublicOrigin: p.Origin}.Resource())
	if e != nil {
		return fail(mounts.ErrUnavailable)
	}
	var seal *kms.Sealer
	var open *kms.Opener
	if providers != nil {
		seal, open = providers.BrowserSealer(), providers.BrowserOpener()
		if seal == nil || open == nil {
			return fail(mounts.ErrUnavailable)
		}
	} else {
		h, e := ownerHTTP(in.config.KeyService.Endpoint, in.config.KeyService.Roots)
		if e != nil {
			return fail(mounts.ErrUnavailable)
		}
		closers = append(closers, h.CloseIdleConnections)
		if seal, e = kms.NewSealerWithTokenSource(in.config.KeyService.Endpoint, p.SessionTransit.Mount, p.SessionTransit.Key, files.token(contracts.OwnerPublicSessionSealToken), h); e != nil {
			return fail(mounts.ErrUnavailable)
		}
		closers = append(closers, seal.Close)
		if open, e = kms.NewOpenerWithTokenSource(in.config.KeyService.Endpoint, p.SessionTransit.Mount, p.SessionTransit.Key, files.token(contracts.OwnerPublicSessionOpenToken), h); e != nil {
			return fail(mounts.ErrUnavailable)
		}
		closers = append(closers, open.Close)
	}
	pool, e := pools.open(ctx, "browser-session")
	if e != nil {
		return fail(e)
	}
	store, e := postgres.NewBrowserSessions(ctx, pool, settings.Binding())
	if e != nil {
		return fail(mounts.ErrUnavailable)
	}
	out := &publicIdentity{settings: settings,
		mcp:      identities.Service{Tokens: mcpTokens, Policies: policies, Now: time.Now},
		download: identities.Service{Tokens: downloadTokens, Policies: policies, Now: time.Now},
		sessions: &identities.BrowserSessions{Store: store, Cipher: kms.BrowserCipher{Sealer: seal, Opener: open}, Provider: provider,
			Identities: identities.Service{Tokens: browserTokens, Policies: policies, Now: time.Now}, Logout: provider,
			Issuer: settings.Issuer, ClientID: settings.ClientID, Epoch: settings.Epoch, Lifetime: time.Duration(settings.MaxLifetimeSeconds) * time.Second, Now: time.Now}}
	if ctx.Err() != nil {
		return fail(mounts.ErrUnavailable)
	}
	return out, closers, nil
}
