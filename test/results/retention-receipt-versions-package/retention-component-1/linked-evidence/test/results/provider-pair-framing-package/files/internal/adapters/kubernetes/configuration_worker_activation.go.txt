package kubernetes

import (
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

// HubWorkerActivationBound validates the complete explicitly selected public
// input. The old profile rejects all provider fields; the new profile requires
// both exact original SQL/input provenance and its derived provider recipe.
// This shape check never replaces an original journal or current native proof.
func HubWorkerActivationBound(in contracts.HubWorkerDeployment) bool {
	if !hubWorkerActivationShapeBound(in) {
		return false
	}
	if in.Activation.WorkerLayout == contracts.HubWorkerInstalledLayout {
		return in.ProviderAuthentication == nil && in.ProviderInputs == nil
	}
	a, p, c := in.Activation, in.ProviderAuthentication, in.ProviderInputs
	if a.WorkerLayout != contracts.HubWorkerProviderInstalledLayout || p == nil || c == nil ||
		providerconfig.ValidateConfigurationProviderAuthentication(in, *p, time.Now()) != nil || p.ServiceAccount != a.ServiceAccount ||
		!authorization.UUID(c.OperationID) || !authorization.UUID(c.ConfigurationSetupID) || c.OperationID == c.ConfigurationSetupID || c.OperationID == a.SetupID || c.ConfigurationSetupID == a.SetupID {
		return false
	}
	prefix := strings.ReplaceAll(in.InstallationID, "-", "")
	if c.ConfigurationRoot.Name != "asservat-configuration-roles-"+prefix || c.SQLProjection.Name != "asservat-configuration-runtime-"+prefix {
		return false
	}
	seen := map[string]bool{}
	for _, uid := range []string{in.Namespace.UID, a.Resources.UID, a.Deployment.UID, a.ServiceAccount.UID, a.OwnerDeployment.UID, c.ConfigurationRoot.UID, c.SQLProjection.UID, p.AuditCredentials.UID} {
		if !authorization.UUID(uid) || seen[uid] {
			return false
		}
		seen[uid] = true
	}
	return true
}
