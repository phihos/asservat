package contracts

import "strings"

// The installed layout is selected before the original object claims. It is
// not a request to migrate, adopt or mutate an existing owner template.
const OwnerInstalledLayout = "asservat-owner-installed/v1"
const OwnerInstalledNativePort = 9444
const OwnerInstalledPublicPort = 9445

// OwnerInstalledOperationPort is the promoted owner's ADR-150 v2 operation
// listener (ADR-197): 9444 serves the native and v1 observation names.
const OwnerInstalledOperationPort = 9448
const OwnerObservationProjectionRoot = "/run/asservat/owner-observation"
const OwnerPublicProjectionRoot = "/run/asservat/public"

// PublicRuntimeProjectionName is the immutable product public-role projection;
// the owner public root projects it together with the operator Secret
// OwnerPublicProjectionName (ADR-184).
func PublicRuntimeProjectionName(installationID string) string {
	return "asservat-public-runtime-" + strings.ReplaceAll(installationID, "-", "")
}

// FederationRuntimeProjectionName is the federation's immutable projection
// of its six SQL logins and audit keys (ADR-193).
func FederationRuntimeProjectionName(installationID string) string {
	return "asservat-federation-runtime-" + strings.ReplaceAll(installationID, "-", "")
}

// FederationAuditKeysFile is the federation projection's MAC key file.
const FederationAuditKeysFile = "federation-audit-keys.json"

// Inputs are validated installation IDs before constructing a workload. These
// names identify fixed, complete projections; they do not grant activation.
func OwnerObservationProjectionName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-owner-observation"
}

func OwnerPublicProjectionName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-owner-public"
}
