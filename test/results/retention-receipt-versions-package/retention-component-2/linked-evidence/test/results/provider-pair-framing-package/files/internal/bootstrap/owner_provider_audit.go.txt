package bootstrap

import (
	"context"
	"net/http"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// Only the two existing owner audit operations are adapted. Each operation
// obtains current exact material once, then retains that original deadline
// through ciphertext creation, conditional write and independent readback.
// AWS credential expiration alone would not bound an already signed request.
type installedOwnerEnrollmentAudit struct {
	input     contracts.OwnerDeployment
	providers *kms.InstalledOwnerProviderEffects
	http      *http.Client
}

var _ auditapp.OwnerEnrollmentWriter = (*installedOwnerEnrollmentAudit)(nil)

func newInstalledOwnerEnrollmentAudit(input contracts.OwnerDeployment, providers *kms.InstalledOwnerProviderEffects) (*installedOwnerEnrollmentAudit, error) {
	if providers == nil || input.ProviderAuthentication == nil {
		return nil, mounts.ErrUnavailable
	}
	h, err := ownerHTTP(input.AuditStore.Endpoint, input.AuditStore.Roots)
	if err != nil {
		return nil, err
	}
	return &installedOwnerEnrollmentAudit{input: input, providers: providers, http: h}, nil
}
func (s *installedOwnerEnrollmentAudit) Close() {
	if s != nil && s.http != nil {
		s.http.CloseIdleConnections()
	}
}

// The original worker2/owner2 pair intrinsically requires non-null immutable
// audit versions. Only this fresh profile reaches this constructor; legacy
// owner audit composition keeps its existing store selection. This chooses the
// adapter contract, not backend policy, accounting or recovery authority.
func (s *installedOwnerEnrollmentAudit) storage(material contracts.OwnerStorageCredential) (*objectstore.Store, error) {
	return objectstore.NewVersionedAudit(s.input.AuditStore.Endpoint, s.input.AuditStore.Region, s.input.AuditStore.Bucket, credentials.NewStaticCredentialsProvider(material.AccessKeyID, material.SecretAccessKey, material.SessionToken), s.http)
}

func (s *installedOwnerEnrollmentAudit) operation(ctx context.Context) (context.Context, *objectstore.OwnerEnrollmentAuditObjects, func(), error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, nil, mounts.ErrUnavailable
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	material, until, err := s.providers.ReadAuditCredentials(call)
	if err != nil || !time.Now().Before(until) {
		end()
		return nil, nil, nil, mounts.ErrUnavailable
	}
	call, narrow := context.WithDeadline(call, until)
	store, err := s.storage(material)
	if err != nil {
		narrow()
		end()
		return nil, nil, nil, err
	}
	return call, &objectstore.OwnerEnrollmentAuditObjects{Store: store, Seal: s.providers.Sealer(), Open: s.providers.Opener()}, func() { narrow(); end(); store.Close() }, nil
}
func (s *installedOwnerEnrollmentAudit) WriteOwnerEnrollment(ctx context.Context, e fleet.OwnerEnrollment) (audit.Receipt, error) {
	if s == nil || !e.Valid() || e.Binding.InstallationID != s.input.InstallationID || e.Binding.ClusterID != s.input.ClusterID || e.SourceUID != s.input.ConfigurationUID {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	call, writer, done, err := s.operation(ctx)
	if err != nil {
		return audit.Receipt{}, err
	}
	defer done()
	r, err := writer.WriteOwnerEnrollment(call, e)
	if err != nil || call.Err() != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return r, nil
}
func (s *installedOwnerEnrollmentAudit) WriteOwnerCertificate(ctx context.Context, c audit.OwnerCertificate) (audit.Receipt, error) {
	if s == nil || !c.Valid() || c.Certificate.Binding.InstallationID != s.input.InstallationID || c.Certificate.Binding.ClusterID != s.input.ClusterID || c.Attempt.Enrollment.SourceUID != s.input.ConfigurationUID {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	call, writer, done, err := s.operation(ctx)
	if err != nil {
		return audit.Receipt{}, err
	}
	defer done()
	r, err := writer.WriteOwnerCertificate(call, c)
	if err != nil || call.Err() != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return r, nil
}
