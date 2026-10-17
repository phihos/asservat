package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

// Read-only current operator protection remains usable after the installation
// Pod has terminated. It performs no Pod replacement, credential read or witness
// mutation. Bootstrap supplies the original immutable inputs and exact scope.
type InitialInstallationReadProtection struct {
	state InitialCredentialStateStore
	scope value.InstallationWitnessScope
}

var _ app.InitialInstallationReadAuthority = (*InitialInstallationReadProtection)(nil)

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

func (s *InitialInstallationReadProtection) CheckInitialInstallationRead(ctx context.Context, scope value.InstallationWitnessScope, plan artifact.Digest) (time.Time, error) {
	if s == nil || ctx == nil || scope != s.scope || plan != s.state.plan {
		return time.Time{}, cfg.ErrInvalid
	}
	until, err := s.state.current(ctx, false)
	if err != nil {
		return time.Time{}, err
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	g := s.state.protection
	raw, err := g.guard.observer.raw(ctx, "/api/v1/namespaces/"+scope.Namespace+"/configmaps/"+g.plan.Configuration, nil)
	var cm core.ConfigMap
	if err != nil || strictGuardJSON(raw, &cm) != nil || cm.APIVersion != "v1" || cm.Kind != "ConfigMap" || !ownerMetadata(cm.ObjectMeta, scope.Namespace, g.plan.Configuration, s.state.inputUID) || cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || len(cm.OwnerReferences) != 0 {
		return time.Time{}, cfg.ErrChanged
	}
	c, err := contracts.DecodeInitialInstaller(bytes.NewBufferString(cm.Data["deployment.json"]))
	canonical, e := json.Marshal(c)
	if err != nil || e != nil || artifact.Digest(sha256.Sum256(canonical)) != plan || !contracts.InitialInstallerFormatSupported(c.Format) || c.InstallationID != scope.InstallationID || c.IssuerEpoch != scope.IssuerEpoch || c.ClusterID != scope.ClusterID || c.Namespace.Name != scope.Namespace || c.Namespace.UID != scope.NamespaceUID || c.Witness.Name != scope.Name || c.Witness.UID != scope.UID || c.WriterAccount.Name != scope.WriterAccount || c.WriterAccount.UID != scope.WriterAccountUID {
		return time.Time{}, cfg.ErrChanged
	}
	// The second native check cannot renew the first original deadline.
	final, err := s.state.current(ctx, false)
	until = identity.Earlier(until, final)
	if err != nil || until.IsZero() || ctx.Err() != nil || !g.guard.observer.now().Before(until) {
		return time.Time{}, cfg.ErrUnavailable
	}
	return until, nil
}
