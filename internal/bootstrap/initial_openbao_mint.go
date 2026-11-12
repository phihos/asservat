package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	bao "github.com/openbao/openbao/api/v2"
)

// One original acknowledged seed claim permits one provider POST. An unknown
// response is spent; neither this helper nor a later process retries issuance.
func mintInitialOpenBaoIssuer(ctx context.Context, desired contracts.InitialBootstrap, claim kube.InitialBootstrapProviderClaim) (string, contracts.InitialProviderParent, error) {
	var zero contracts.InitialProviderParent
	s := claim.State
	if ctx == nil || ctx.Err() != nil || !claim.Fresh || s.Material == nil || s.Material.BundledIdentity == nil || s.ProviderMint == nil || s.ProviderMint.Response != nil || desired.Providers != contracts.SmallOpenBaoInitialProviders() || desired.KeyService.Endpoint != s.Material.BundledIdentity.Endpoint() {
		return "", zero, initialOpenBaoCheck("mint-claim")
	}
	ctx, cancel := context.WithDeadline(ctx, claim.ValidUntil)
	defer cancel()
	h, err := ownerHTTP(desired.KeyService.Endpoint, desired.KeyService.Roots)
	if err != nil {
		return "", zero, initialOpenBaoCheck("mint-tls")
	}
	defer h.CloseIdleConnections()
	h.Transport.(*http.Transport).DisableKeepAlives = true
	return mintInitialOpenBaoIssuerWithHTTP(ctx, desired, claim, h)
}

func mintInitialOpenBaoIssuerWithHTTP(ctx context.Context, desired contracts.InitialBootstrap, claim kube.InitialBootstrapProviderClaim, h *http.Client) (string, contracts.InitialProviderParent, error) {
	var zero contracts.InitialProviderParent
	s := claim.State
	if !claim.Fresh || s.Material == nil || s.Material.BundledIdentity == nil || !s.Material.BundledIdentity.Valid() || s.Material.SetupToken == "" || s.Material.IssuerToken != "" || s.ProviderMint == nil || s.ProviderMint.Response != nil || !time.Now().Before(claim.ValidUntil) || !time.Now().Before(s.ProviderMint.Until) || ctx == nil || ctx.Err() != nil {
		return "", zero, initialOpenBaoCheck("mint-claim")
	}
	profile := contracts.InitialProviderProfile{Format: contracts.InitialProviderProfileFormat, Material: contracts.WorkerObjectReference{Name: desired.Name + "-bootstrap-state", UID: s.SeedUID}, IssuerPolicy: desired.Providers.IssuerPolicy, WrapRole: desired.Providers.WrapRole, WrapPolicy: desired.Providers.WrapPolicy, UnwrapRole: desired.Providers.UnwrapRole, UnwrapPolicy: desired.Providers.UnwrapPolicy}
	if !providerconfig.InitialProviderProfile(profile) {
		return "", zero, initialOpenBaoCheck("mint-profile")
	}
	c, err := bao.NewClient(&bao.Config{Address: desired.KeyService.Endpoint, HttpClient: h, MaxRetries: 0, DisableRedirects: true, DisableEnvironment: true})
	if err != nil {
		return "", zero, initialOpenBaoCheck("mint-client")
	}
	c.SetToken(s.Material.SetupToken)
	// A late POST cannot move the child's expiry beyond the original bound.
	seconds := int64(s.ProviderMint.ExpiresBefore.Sub(s.ProviderMint.Until)/time.Second) - 1
	if seconds < 1 || seconds > 900 {
		return "", zero, initialOpenBaoCheck("mint-expiry")
	}
	no := false
	response, err := c.Auth().Token().CreateWithRoleWithContext(ctx, &bao.TokenCreateRequest{Policies: []string{desired.Providers.IssuerPolicy}, NoDefaultPolicy: true, Renewable: &no, Type: "service", TTL: fmt.Sprintf("%ds", seconds), ExplicitMaxTTL: fmt.Sprintf("%ds", seconds), Metadata: map[string]string{"asservat-installation": s.InstallationID, "asservat-request": s.RequestID, "asservat-operation": s.ProviderMint.OperationID}}, contracts.SmallOpenBaoInitialIssuerRole)
	if err != nil || response == nil || response.Auth == nil || len(response.Warnings) != 0 || response.WrapInfo != nil || !kms.ValidProviderToken([]byte(response.Auth.ClientToken)) || len(response.Auth.ClientToken) > contracts.InitialProviderTokenMaxBytes || ctx.Err() != nil {
		return "", zero, initialOpenBaoCheck("mint-response")
	}
	issuer, err := kms.NewBundledInitialProviderIssuer(desired.KeyService.Endpoint, response.Auth.ClientToken, desired.KeyService.AuditMount, desired.KeyService.AuditKey, s.InstallationID, s.RequestID, profile, *s.Material.BundledIdentity, h, time.Now)
	if err != nil {
		return "", zero, initialOpenBaoCheck("mint-profile")
	}
	defer issuer.Close()
	parent, _, err := issuer.Check(ctx, s.ProviderMint.ExpiresBefore)
	if err != nil {
		stage := "mint-verification"
		if phase := kms.InitialProviderCheckStage(err); phase != "" {
			stage += "/" + phase
		}
		return "", zero, initialOpenBaoCheck(stage)
	}
	if parent.Accessor != response.Auth.Accessor || parent.Accessor == s.Material.BundledIdentity.SetupParent.Accessor || parent.IssuedAt.Before(s.ProviderMint.StartedAt) || parent.IssuedAt.After(s.ProviderMint.Until) || parent.ExpiresAt.After(s.ProviderMint.ExpiresBefore) || !time.Now().Before(claim.ValidUntil) || ctx.Err() != nil {
		return "", zero, initialOpenBaoCheck("mint-verification")
	}
	return response.Auth.ClientToken, parent, nil
}

func (d *initialBootstrapProcess) completeSmallKeyProvider() error {
	if d.services.KeyService == nil || d.state.Material == nil || d.state.Material.SetupToken == "" {
		return nil
	}
	claim, err := d.producer.ClaimBundledProvider(d.root)
	if err != nil || !claim.Fresh {
		return initialOpenBaoCheck("mint-original-claim")
	}
	token, parent, err := mintInitialOpenBaoIssuer(d.root, d.desired, claim)
	if err != nil {
		return err
	}
	if err := d.producer.CompleteBundledProvider(d.root, claim, token, parent); err != nil {
		return initialOpenBaoCheck("mint-record")
	}
	d.state, err = d.producer.Open(d.root, nil)
	if err != nil || d.state.Material == nil || d.state.Material.SetupToken != "" || d.state.Material.IssuerToken != token {
		return mounts.ErrUnavailable
	}
	return nil
}
