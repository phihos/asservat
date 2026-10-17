package providerconfig

import (
	"regexp"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"k8s.io/apimachinery/pkg/util/validation"
)

var initialProviderName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// This is pure input validation. It supplies no current provider, source,
// credential-issue or installation authority.
func InitialProviderProfile(p contracts.InitialProviderProfile) bool {
	if p.Format != contracts.InitialProviderProfileFormat || !authorization.UUID(p.Material.UID) || len(validation.IsDNS1123Subdomain(p.Material.Name)) != 0 {
		return false
	}
	return InitialProviderNames(p.IssuerPolicy, p.WrapRole, p.WrapPolicy, p.UnwrapRole, p.UnwrapPolicy)
}

// InitialProviderNames validates static bootstrap input before private state or
// provider effects. The full profile separately requires its original material
// identity; valid names alone are never provider or installation authority.
func InitialProviderNames(issuerPolicy, wrapRole, wrapPolicy, unwrapRole, unwrapPolicy string) bool {
	names := []string{issuerPolicy, wrapRole, wrapPolicy, unwrapRole, unwrapPolicy}
	seen := map[string]bool{}
	for _, name := range names {
		if !initialProviderName.MatchString(name) || seen[name] || name == "root" || name == "default" {
			return false
		}
		seen[name] = true
	}
	return true
}
