package kubernetes

import (
	"strings"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Fixed original namespace source. It is never selected by a capture caller.
func installedProcessingSource(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-processing-source"
}

// ownerPublicSourceProbes are the provider-installed hub-api's guarded public
// sources (ADR-185): the cluster catalog, each regional slot's capability and
// work trust, the worker configuration and the download environment. The owner
// account proves each source's own denial with a dry-run UPDATE.
func ownerPublicSourceProbes(installationID, ownerAccount string) []cfg.OwnerConfigurationProbe {
	names := contracts.OwnerPublicGuardedSources(installationID)
	out := make([]cfg.OwnerConfigurationProbe, 0, len(names))
	for _, name := range names {
		out = append(out, cfg.OwnerConfigurationProbe{ConfigMap: name, ServiceAccount: ownerAccount})
	}
	return out
}
