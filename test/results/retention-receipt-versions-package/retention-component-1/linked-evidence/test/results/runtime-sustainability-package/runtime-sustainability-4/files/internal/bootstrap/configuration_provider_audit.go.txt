package bootstrap

import (
	"context"
	"net/http"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// This worker-only adapter retains the original current material deadline for
// the complete encrypted write and independent readback. SDK credential expiry
// alone does not bound an HTTP request which has already been signed.
type installedConfigurationAudit struct {
	input     contracts.HubWorkerDeployment
	providers *kms.InstalledConfigurationProviderEffects
	http      *http.Client
}

var _ auditapp.OwnerConfigurationWriter = (*installedConfigurationAudit)(nil)

func newInstalledConfigurationAudit(input contracts.HubWorkerDeployment, providers *kms.InstalledConfigurationProviderEffects) (*installedConfigurationAudit, error) {
	if providers == nil || input.ProviderAuthentication == nil || input.ProviderInputs == nil || input.Activation == nil || input.Activation.WorkerLayout != contracts.HubWorkerProviderInstalledLayout {
		return nil, mounts.ErrUnavailable
	}
	h, err := ownerHTTP(input.AuditStore.Endpoint, input.AuditStore.Roots)
	if err != nil {
		return nil, err
	}
	return &installedConfigurationAudit{input: input, providers: providers, http: h}, nil
}

func (s *installedConfigurationAudit) Close() {
	if s != nil && s.http != nil {
		s.http.CloseIdleConnections()
	}
}

// The fresh paired layout requires immutable non-null versions. It never
// discovers a storage profile from a response or falls back to unversioned I/O.
// The protected installation still qualifies IAM, accounting, cleanup/recovery.
func (s *installedConfigurationAudit) storage(material contracts.OwnerStorageCredential) (*objectstore.Store, error) {
	return objectstore.NewVersionedAudit(s.input.AuditStore.Endpoint, s.input.AuditStore.Region, s.input.AuditStore.Bucket,
		credentials.NewStaticCredentialsProvider(material.AccessKeyID, material.SecretAccessKey, material.SessionToken), s.http)
}

func (s *installedConfigurationAudit) WriteOwnerConfiguration(ctx context.Context, c fleet.OwnerConfiguration) (audit.Receipt, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.providers == nil || !c.Valid() || c.Pool.InstallationID != s.input.InstallationID || c.Pool.ClusterID != s.input.ClusterID || c.Pool.NamespaceUID != s.input.Namespace.UID || c.Revision.UID != s.input.OwnerSource.UID {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	operation, err := s.providers.BeginOwnerConfigurationAudit(ctx, c)
	if err != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	defer operation.Close()
	call := operation.Context()
	material, err := operation.Credentials()
	if err != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	store, err := s.storage(material)
	if err != nil {
		return audit.Receipt{}, err
	}
	defer store.Close()
	writer := &objectstore.OwnerConfigurationAuditObjects{Store: store, Seal: s.providers.Sealer(), Open: s.providers.Opener()}
	receipt, err := writer.WriteOwnerConfiguration(call, c)
	if err != nil || call.Err() != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	if err = operation.Finish(); err != nil || call.Err() != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return receipt, nil
}
