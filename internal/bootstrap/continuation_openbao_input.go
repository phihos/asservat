package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"k8s.io/client-go/rest"
)

// resolveInstallerContinuationKeyService consumes only an explicitly selected
// bundled source. It checks the original preparer before any setup login and
// reads existing provider prerequisites; it creates no mount, issuer or role.
func resolveInstallerContinuationKeyService(ctx context.Context, files *os.Root, input *contracts.InstallerContinuation, original contracts.InitialPreparer, config *rest.Config) (*initialOpenBaoProvider, error) {
	return resolveInstallerContinuationKeyServiceWithOpen(ctx, files, input, original, config, openInitialOpenBaoProvider)
}

func resolveInstallerContinuationKeyServiceWithOpen(ctx context.Context, files *os.Root, input *contracts.InstallerContinuation, original contracts.InitialPreparer, config *rest.Config, open func(context.Context, *os.Root, contracts.SmallOpenBaoPlan, *rest.Config) (*initialOpenBaoProvider, error)) (_ *initialOpenBaoProvider, err error) {
	if ctx == nil || ctx.Err() != nil || files == nil || input == nil {
		return nil, mounts.ErrUnavailable
	}
	if input.KeyServiceSource == "" {
		return nil, nil
	}
	if input.KeyServiceSource != contracts.InitialBootstrapBundledOpenBaoRoots || !initialOpenBaoCurrent(ctx) || original.Services == nil || !strings.HasSuffix(original.Plan.RootName, "-preparation") || open == nil {
		return nil, initialOpenBaoCheck("continuation-source")
	}
	name := strings.TrimSuffix(original.Plan.RootName, "-preparation")
	plan, ca, _, err := readBundledOpenBaoSource(ctx, files, input.Namespace, name)
	if err != nil {
		return nil, initialOpenBaoCheck("continuation-source")
	}
	roots, err := providerconfig.TrustRootsPEM(ca, time.Now())
	if err != nil || !continuationKeyServiceMatchesOriginal(plan, roots, *input, original) {
		return nil, initialOpenBaoCheck("continuation-original")
	}
	// Empty fields select the fixed prerequisites only for this explicit profile.
	// Supplied values must match; the ordinary external provider path is unchanged.
	normalized := *input
	if normalized.WorkerProvider.AuthMount != "" && normalized.WorkerProvider.AuthMount != contracts.SmallOpenBaoConfigurationAuthMount || normalized.OwnerProvider.AuthMount != "" && normalized.OwnerProvider.AuthMount != contracts.SmallOpenBaoOwnerAuthMount || normalized.OwnerPKIMount != "" && normalized.OwnerPKIMount != contracts.SmallOpenBaoOwnerPKIMount {
		return nil, initialOpenBaoCheck("continuation-mount")
	}
	if normalized.Public != nil && normalized.Public.Federation != nil {
		mount := normalized.Public.Federation.ConnectorPKIMount
		if mount != "" && mount != contracts.SmallOpenBaoConnectorPKIMount {
			return nil, initialOpenBaoCheck("continuation-connector-mount")
		}
	}
	provider, err := open(ctx, files, plan, config)
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			provider.Close()
		}
	}()
	// The original preparer was already checked natively. Consume the same
	// operation's actual namespace reference without another API observation.
	if provider == nil || provider.Identity.Namespace != original.Plan.BootstrapNamespace {
		return nil, initialOpenBaoCheck("continuation-namespace")
	}
	worker, err := continuationOpenBaoAuthAccessor(ctx, provider, contracts.SmallOpenBaoConfigurationAuthMount)
	if err != nil {
		return nil, initialOpenBaoCheck("continuation-worker-auth")
	}
	owner, err := continuationOpenBaoAuthAccessor(ctx, provider, contracts.SmallOpenBaoOwnerAuthMount)
	if err != nil {
		return nil, initialOpenBaoCheck("continuation-owner-auth")
	}
	if normalized.WorkerProvider.AuthMountAccessor != "" && normalized.WorkerProvider.AuthMountAccessor != worker || normalized.OwnerProvider.AuthMountAccessor != "" && normalized.OwnerProvider.AuthMountAccessor != owner {
		return nil, initialOpenBaoCheck("continuation-accessor")
	}
	issuer, err := initialOpenBaoCall(ctx, provider.HTTP, plan.Endpoint(), string(provider.Token), http.MethodGet, contracts.SmallOpenBaoOwnerPKIMount+"/cert/ca", nil)
	var certificate struct {
		Certificate string `json:"certificate"`
	}
	if err != nil || json.Unmarshal(issuer.Data, &certificate) != nil || certificate.Certificate == "" {
		return nil, initialOpenBaoCheck("continuation-owner-issuer")
	}
	issuerRoots, err := providerconfig.TrustRootsPEM([]byte(certificate.Certificate), time.Now())
	if err != nil || len(issuerRoots) != 1 {
		return nil, initialOpenBaoCheck("continuation-owner-issuer")
	}
	if normalized.OwnerIssuerRootsPEM != "" {
		supplied, err := providerconfig.TrustRootsPEM([]byte(normalized.OwnerIssuerRootsPEM), time.Now())
		if err != nil || !reflect.DeepEqual(supplied, issuerRoots) {
			return nil, initialOpenBaoCheck("continuation-owner-roots")
		}
	} else {
		normalized.OwnerIssuerRootsPEM = certificate.Certificate
	}
	if normalized.Public != nil && normalized.Public.Federation != nil {
		federation := *normalized.Public.Federation
		reply, err := initialOpenBaoCall(ctx, provider.HTTP, plan.Endpoint(), string(provider.Token), http.MethodGet, contracts.SmallOpenBaoConnectorPKIMount+"/cert/ca", nil)
		var certificate struct {
			Certificate string `json:"certificate"`
		}
		if err != nil || json.Unmarshal(reply.Data, &certificate) != nil || certificate.Certificate == "" {
			return nil, initialOpenBaoCheck("continuation-connector-issuer")
		}
		roots, err := providerconfig.TrustRootsPEM([]byte(certificate.Certificate), time.Now())
		if err != nil || len(roots) != 1 {
			return nil, initialOpenBaoCheck("continuation-connector-issuer")
		}
		if federation.ConnectorIssuerRootsPEM != "" {
			supplied, err := providerconfig.TrustRootsPEM([]byte(federation.ConnectorIssuerRootsPEM), time.Now())
			if err != nil || !reflect.DeepEqual(supplied, roots) {
				return nil, initialOpenBaoCheck("continuation-connector-roots")
			}
		} else {
			federation.ConnectorIssuerRootsPEM = certificate.Certificate
		}
		federation.ConnectorPKIMount = contracts.SmallOpenBaoConnectorPKIMount
		public := *normalized.Public
		public.Federation = &federation
		normalized.Public = &public
	}
	if !initialOpenBaoCurrent(ctx) {
		return nil, initialOpenBaoCheck("continuation-context")
	}
	normalized.WorkerProvider = contracts.InstallerProviderSelection{AuthMount: contracts.SmallOpenBaoConfigurationAuthMount, AuthMountAccessor: worker}
	normalized.OwnerProvider = contracts.InstallerProviderSelection{AuthMount: contracts.SmallOpenBaoOwnerAuthMount, AuthMountAccessor: owner}
	normalized.OwnerPKIMount = contracts.SmallOpenBaoOwnerPKIMount
	normalized.KeyServiceSource = ""
	*input = normalized
	complete = true
	return provider, nil
}

func continuationKeyServiceMatchesOriginal(plan contracts.SmallOpenBaoPlan, roots [][]byte, input contracts.InstallerContinuation, original contracts.InitialPreparer) bool {
	return plan.Valid() && original.Services != nil && plan.Namespace == input.Namespace && plan.Namespace == original.Plan.BootstrapNamespace.Name && plan.Name+"-preparation" == original.Plan.RootName && plan.Endpoint() == original.Services.KeyService.Endpoint && reflect.DeepEqual(roots, original.Services.KeyService.Roots) && reflect.DeepEqual(plan.Kubernetes, original.Kubernetes) && reflect.DeepEqual(plan.Kubernetes, original.Services.Kubernetes)
}

// These fixed named metadata reads never enable authentication or generate an
// issuer. Missing prerequisites are a provisioning-phase failure, not fallback.
func continuationOpenBaoAuthAccessor(ctx context.Context, provider *initialOpenBaoProvider, mount string) (string, error) {
	reply, err := initialOpenBaoCall(ctx, provider.HTTP, provider.Plan.Endpoint(), string(provider.Token), http.MethodGet, "sys/mounts/auth/"+mount, nil)
	var value struct {
		Type     string `json:"type"`
		Accessor string `json:"accessor"`
		Config   struct {
			DefaultTTL *int64 `json:"default_lease_ttl"`
			MaximumTTL *int64 `json:"max_lease_ttl"`
			TokenType  string `json:"token_type"`
		} `json:"config"`
	}
	if err != nil || json.Unmarshal(reply.Data, &value) != nil || value.Type != "kubernetes" || !ownerProviderName.MatchString(value.Accessor) || value.Config.DefaultTTL == nil || value.Config.MaximumTTL == nil || *value.Config.DefaultTTL < 0 || *value.Config.MaximumTTL < 0 || value.Config.TokenType != "default-service" && value.Config.TokenType != "default-batch" && value.Config.TokenType != "service" {
		return "", mounts.ErrUnavailable
	}
	return value.Accessor, nil
}
