package contracts

import (
	"io"
	"strconv"
	"strings"
)

// ADR-185: the regional clusters the promoted hub-api serves come from one
// guarded, administrator-written catalog instead of the immutable owner input.
// Catalog membership is not authority: each entry is accepted only after its
// connector peer matches current SQL activation and its sources pass their
// own guards.
const (
	OwnerClusterCatalogFormat   = "asservat-owner-cluster-catalog/v1"
	OwnerClusterCatalogFile     = "cluster-catalog.json"
	OwnerClusterCatalogMaxBytes = 128 << 10
	// OwnerClusterCatalogSlots is the installation's fixed regional capacity.
	// Slot names are deterministic, so the owner Role and the namespace
	// workload guard name every slot's capability and work-trust sources
	// (two dry-run probe pairs per slot) at install time; an unused slot's
	// names grant nothing because its sources do not exist. Eight covers the
	// S-02 second cluster with headroom, keeps the catalog (about 6 KiB per
	// entry) well under its 128 KiB bound and stays below the context-start
	// router's 16-cluster limit.
	OwnerClusterCatalogSlots = 8
)

type OwnerClusterCatalog struct {
	Format   string               `json:"format"`
	Clusters []OwnerPublicCluster `json:"clusters"`
}

func DecodeOwnerClusterCatalog(r io.Reader) (OwnerClusterCatalog, error) {
	return decodeClosedRPC[OwnerClusterCatalog](r, OwnerClusterCatalogMaxBytes)
}

// The download sources the promoted hub-api reads (ADR-185), fixed per
// installation so the owner workload guard and Role can name them.
func OwnerWorkerConfigurationName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-worker-configuration"
}
func OwnerDownloadEnvironmentName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-download-environment"
}

func OwnerBrowserSettingsName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-browser-settings"
}
func OwnerIdentitySettingsName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-identity-settings"
}

// OwnerPublicGuardedSources are the provider-installed hub-api's guarded
// public sources in their fixed order; each guard is named source + "-guard".
func OwnerPublicGuardedSources(installationID string) []string {
	out := []string{OwnerClusterCatalogName(installationID)}
	for slot := 1; slot <= OwnerClusterCatalogSlots; slot++ {
		out = append(out, OwnerClusterSourceName(installationID, slot, "capability"), OwnerClusterSourceName(installationID, slot, "work-trust"))
	}
	return append(out, OwnerWorkerConfigurationName(installationID), OwnerDownloadEnvironmentName(installationID))
}

// OwnerClusterTopologyNames are the fixed per-slot retention topology
// ConfigMaps (ADR-196 decision 7). They are immutable and pinned by digest in
// the catalog entry, so they need no guard or probe.
func OwnerClusterTopologyNames(installationID string) []string {
	out := make([]string, 0, OwnerClusterCatalogSlots)
	for slot := 1; slot <= OwnerClusterCatalogSlots; slot++ {
		out = append(out, OwnerClusterSourceName(installationID, slot, "topology"))
	}
	return out
}

func OwnerClusterCatalogName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-cluster-catalog"
}

// OwnerClusterSourceName is a fixed per-slot source name, so the owner Role
// can name it before any cluster enrolls. kind is "capability" or
// "work-trust"; slot counts from 1.
func OwnerClusterSourceName(installationID string, slot int, kind string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-cluster-" + strconv.Itoa(slot) + "-" + kind
}
