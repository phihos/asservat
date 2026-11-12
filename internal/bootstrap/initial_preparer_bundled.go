package bootstrap

import (
	"net/http"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// Select only the original explicitly retained bundled identity. External
// provider material continues through its existing empty-entity profile.
func initialPreparerIssuer(c contracts.InitialPreparer, material contracts.InitialProviderMaterial, h *http.Client, now func() time.Time) (*kms.InitialProviderIssuer, error) {
	if c.Services == nil || c.Providers == nil {
		return nil, mounts.ErrUnavailable
	}
	k := c.Services.KeyService
	if b := material.BundledIdentity; b != nil {
		if !b.Valid() || b.Namespace != c.Plan.BootstrapNamespace || b.BackendName != strings.TrimSuffix(c.Plan.RootName, "-preparation") || k.Endpoint != b.Endpoint() {
			return nil, mounts.ErrUnavailable
		}
		return kms.NewBundledInitialProviderIssuer(k.Endpoint, material.IssuerToken, k.AuditMount, k.AuditKey, c.Plan.InstallationID, c.Plan.RequestID, *c.Providers, *b, h, now)
	}
	return kms.NewInitialProviderIssuer(k.Endpoint, material.IssuerToken, k.AuditMount, k.AuditKey, c.Plan.InstallationID, c.Plan.RequestID, *c.Providers, h, now)
}
