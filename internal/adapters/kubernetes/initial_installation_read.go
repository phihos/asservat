package kubernetes

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Read-only current operator protection remains usable after the installation
// Pod has terminated. It performs no Pod replacement, credential read or witness
// mutation. Bootstrap supplies the original immutable inputs and exact scope.
type InitialInstallationReadProtection struct {
	state InitialCredentialStateStore
	scope value.InstallationWitnessScope
}

func NewInitialInstallationReadProtection(administrator, probe *PermissionClient, workload cfg.InitialWorkloadAdministration, pin GuardPin, inputUID string, scope value.InstallationWitnessScope, plan artifact.Digest) (*InitialInstallationReadProtection, error) {
	if !scope.Valid() || !authorization.UUID(inputUID) || plan == (artifact.Digest{}) || workload.ControlNamespace.Name != scope.Namespace || workload.ControlNamespace.UID != scope.NamespaceUID || workload.Witness != scope.Name || workload.WriterAccount != scope.WriterAccount || workload.WriterAccountUID != scope.WriterAccountUID || administrator == nil || administrator.clusterID != scope.ClusterID {
		return nil, cfg.ErrInvalid
	}
	g, err := NewInitialWorkloadProtection(administrator, probe, workload, pin)
	if err != nil {
		return nil, err
	}
	return &InitialInstallationReadProtection{state: InitialCredentialStateStore{protection: g, inputUID: inputUID, installation: scope.InstallationID, plan: plan}, scope: scope}, nil
}
