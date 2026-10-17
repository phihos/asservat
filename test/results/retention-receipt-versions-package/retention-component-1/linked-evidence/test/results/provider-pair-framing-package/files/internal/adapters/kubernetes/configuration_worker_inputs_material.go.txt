package kubernetes

import (
	"encoding/json"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Derive from the actual original installer and fixed resource receipts, not
// caller-supplied ConfigMap bytes or an already accepted owner configuration.
// The caller still owns the retained bridge/SQL/provider observation and the
// one CREATE disposition; this pure construction establishes no authority.
func (s *InitialRuntimeResources) configurationWorkerInputMaterial(resources contracts.InitialRuntimeResourceSnapshot, roles contracts.ConfigurationRuntimeRoleSnapshot, operation string, now time.Time) (contracts.HubWorkerDeployment, string, []byte, error) {
	var zero contracts.HubWorkerDeployment
	v, r := resources.State, roles.State
	if s == nil || !authorization.UUID(operation) || !authorization.UUID(roles.UID) || !authorization.UUID(r.OperationID) ||
		v.WorkerLayout != contracts.HubWorkerProviderInstalledLayout || v.OwnerLayout != contracts.OwnerProviderInstalledLayout || v.WorkerProvider == nil ||
		!configurationRoleStateValid(r.Input, r, now) || r.Projection == nil || !authorization.UUID(r.Projection.SecretUID) ||
		r.Input.InstallationID != s.initial.InstallationID || r.Input.InitialClaimID == "" || r.Input.ClusterID != s.initial.ClusterID {
		return zero, "", nil, cfg.ErrChanged
	}
	inventory, err := s.inventory(v)
	if err != nil || r.Input.Namespace != inventory.Namespace || r.Input.Deployment != inventory.WorkerDeployment ||
		r.Input.ServiceAccount != inventory.WorkerAccount || r.Input.FleetSource != inventory.FleetSource || r.Input.OwnerSource != inventory.OwnerSource {
		return zero, "", nil, cfg.ErrChanged
	}
	activation, err := BuildHubWorkerActivation(s.initial.InstallationID, resources, inventory)
	if err != nil {
		return zero, "", nil, err
	}
	sql := s.initial.Postgres
	sql.MaxConnections = 1
	in := contracts.HubWorkerDeployment{Format: contracts.HubWorkerDeploymentFormat,
		InstallationID: s.initial.InstallationID, ClusterID: s.initial.ClusterID, Namespace: inventory.Namespace,
		FleetSource: inventory.FleetSource, OwnerSource: inventory.OwnerSource, FleetGuard: inventory.FleetGuard,
		OwnerGuard: inventory.OwnerSourceGuard, LeaderLease: inventory.LeaderLease,
		Kubernetes: s.initial.Kubernetes, Postgres: sql, AuditStore: s.initial.AuditStore, KeyService: s.initial.KeyService, Activation: activation,
		ProviderInputs: &contracts.ConfigurationWorkerInputProvenance{OperationID: operation,
			ConfigurationRoot:    contracts.WorkerObjectReference{Name: configurationWorkerRoleRootName(s.initial.InstallationID), UID: roles.UID},
			ConfigurationSetupID: r.OperationID,
			SQLProjection:        contracts.WorkerObjectReference{Name: configurationWorkerSQLProjectionName(s.initial.InstallationID), UID: r.Projection.SecretUID}}}
	recipe, err := providerconfig.ConfigurationProviderRecipeFor(in, *v.WorkerProvider, inventory.WorkerAccount, now)
	if err != nil {
		return zero, "", nil, cfg.ErrChanged
	}
	in.ProviderAuthentication = &recipe.Profile
	if !HubWorkerActivationBound(in) {
		return zero, "", nil, cfg.ErrChanged
	}
	digest, err := configurationWorkerInputDigest(in)
	if err != nil {
		return zero, "", nil, err
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > contracts.OwnerDeploymentMaxBytes {
		return zero, "", nil, cfg.ErrInvalid
	}
	return in, digest, raw, nil
}

func configurationWorkerRoleRootName(installation string) string {
	return "asservat-configuration-roles-" + strings.ReplaceAll(installation, "-", "")
}
func configurationWorkerSQLProjectionName(installation string) string {
	return "asservat-configuration-runtime-" + strings.ReplaceAll(installation, "-", "")
}
