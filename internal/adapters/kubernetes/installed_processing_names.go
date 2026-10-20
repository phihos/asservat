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
// account proves each source's own denial with a dry-run UPDATE. The publisher
// reads the catalog with the same proof (ADR-203 decision 6), so its account
// gets the one catalog pair; without it the namespace guard, not the catalog's
// own guard, would deny its probe. The key service reads the catalog the same
// way when it authorizes acquisition unwraps (ADR-204 decision 8).
func ownerPublicSourceProbes(installationID, ownerAccount string) []cfg.OwnerConfigurationProbe {
	names := contracts.OwnerPublicGuardedSources(installationID)
	out := make([]cfg.OwnerConfigurationProbe, 0, len(names)+2)
	for _, name := range names {
		out = append(out, cfg.OwnerConfigurationProbe{ConfigMap: name, ServiceAccount: ownerAccount})
	}
	// ADR-210: the owner also proves the processing source's own denial.
	out = append(out, cfg.OwnerConfigurationProbe{ConfigMap: installedProcessingSource(installationID), ServiceAccount: ownerAccount})
	catalog := contracts.OwnerClusterCatalogName(installationID)
	return append(out, cfg.OwnerConfigurationProbe{ConfigMap: catalog, ServiceAccount: contracts.PublisherName(installationID)},
		cfg.OwnerConfigurationProbe{ConfigMap: catalog, ServiceAccount: contracts.KeyServiceName(installationID)})
}

// ownerRuntimeProbeAccounts are the promoted runtime accounts besides the
// owner's whose catalog pairs ownerPublicSourceProbes adds; each proves the
// catalog's own denial at read time, so the bridge proves none of them.
func ownerRuntimeProbeAccounts(installationID string) []string {
	return []string{contracts.PublisherName(installationID), contracts.KeyServiceName(installationID)}
}
