package bootstrap

import (
	"net/http"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/contracts"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// This worker-only adapter retains the original current material deadline for
// the complete encrypted write and independent readback. SDK credential expiry
// alone does not bound an HTTP request which has already been signed.
type installedConfigurationAudit struct {
	store     contracts.OwnerAuditStore
	providers *kms.InstalledConfigurationProviderEffects
	http      *http.Client
}

func newInstalledConfigurationAudit(store contracts.OwnerAuditStore, providers *kms.InstalledConfigurationProviderEffects) (*installedConfigurationAudit, error) {
	if providers == nil {
		return nil, mounts.ErrUnavailable
	}
	h, err := ownerHTTP(store.Endpoint, store.Roots)
	if err != nil {
		return nil, err
	}
	return &installedConfigurationAudit{store: store, providers: providers, http: h}, nil
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
	return objectstore.NewVersionedAudit(s.store.Endpoint, s.store.Region, s.store.Bucket,
		credentials.NewStaticCredentialsProvider(material.AccessKeyID, material.SecretAccessKey, material.SessionToken), s.http)
}
