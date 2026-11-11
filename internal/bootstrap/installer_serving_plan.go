package bootstrap

import (
	"net/url"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

func (k *InstallerContinuation) servingTLSPlan() (contracts.InstallerServingTLSPlan, error) {
	var plan contracts.InstallerServingTLSPlan
	if k.input.Public == nil || k.input.Public.Federation == nil {
		return plan, nil
	}
	f := k.input.Public.Federation
	plan.FederationServerName = f.ServerName
	if f.KeyServiceEndpoint != "" {
		endpoint, err := url.Parse(f.KeyServiceEndpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.Path != "" {
			return plan, mounts.ErrUnavailable
		}
		plan.KeyServiceServerName = endpoint.Hostname()
	}
	return plan, nil
}
