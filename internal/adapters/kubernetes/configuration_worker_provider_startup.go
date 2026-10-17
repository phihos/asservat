package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// VerifyProjected checks the original native material before a loader opens
// SQL credentials. The manifest's original common epoch is a comparison pin,
// not current recovery authority. Verify still independently reads the exact
// immutable Secret, current protected sources, guard and actual Pod identity.
// The loader must separately authenticate every SQL role and all provider I/O
// must consume the concrete current RecoveryReader after that authentication.
func (s *ConfigurationWorkerProviderReader) VerifyProjected(ctx context.Context, manifest contracts.ConfigurationRuntimeCredentialManifest, mounted map[string][]byte) (time.Time, error) {
	if s == nil || s.worker == nil {
		return time.Time{}, cfg.ErrInvalid
	}
	epoch, err := configurationProjectedEpoch(s.worker.input, manifest)
	if err != nil {
		return time.Time{}, err
	}
	return s.Verify(ctx, epoch, manifest, mounted)
}

func configurationProjectedEpoch(in contracts.HubWorkerDeployment, m contracts.ConfigurationRuntimeCredentialManifest) (string, error) {
	if in.Activation == nil || in.ProviderInputs == nil || m.Format != contracts.ConfigurationRuntimeCredentialManifestFormat ||
		m.Input.InstallationID != in.InstallationID || m.Input.ClusterID != in.ClusterID || m.Input.Namespace != in.Namespace ||
		m.Input.Deployment != in.Activation.Deployment || m.Input.ServiceAccount != in.Activation.ServiceAccount ||
		m.Input.FleetSource != in.FleetSource || m.Input.OwnerSource != in.OwnerSource ||
		m.RootUID != in.ProviderInputs.ConfigurationRoot.UID || m.SetupID != in.ProviderInputs.ConfigurationSetupID {
		return "", cfg.ErrChanged
	}
	purposes := contracts.ConfigurationRuntimeRolePurposes()
	if len(m.Roles) != len(purposes) {
		return "", cfg.ErrChanged
	}
	epoch := ""
	for i, role := range m.Roles {
		s := role.Claim.Sources
		if role.Purpose != purposes[i] || !authorization.UUID(s.IssuerEpoch) ||
			s.InstallationID != in.InstallationID || s.ClusterID != in.ClusterID || s.NamespaceUID != in.Namespace.UID ||
			s.DeploymentUID != in.Activation.Deployment.UID || s.AccountUID != in.Activation.ServiceAccount.UID ||
			s.Fleet.UID != in.FleetSource.UID || s.Owner.UID != in.OwnerSource.UID || epoch != "" && s.IssuerEpoch != epoch {
			return "", cfg.ErrChanged
		}
		epoch = s.IssuerEpoch
	}
	return epoch, nil
}
