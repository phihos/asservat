package kubernetes

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/apimachinery/pkg/util/validation"
)

// InitialCredentialStateStore is a trusted provisioning facet, not the
// activation Pod's client. It cannot create a namespace, guard, account or Pod.
// The independently pinned clean namespace must already have been established.
type InitialCredentialStateStore struct {
	protection                   *InitialWorkloadProtection
	inputUID, installation, name string
	plan                         artifact.Digest
}

func NewInitialCredentialStateStore(administrator, probe *PermissionClient, workload cfg.InitialWorkloadAdministration, pin GuardPin, inputUID, installation, name string, plan artifact.Digest) (*InitialCredentialStateStore, error) {
	if !authorization.UUID(inputUID) || !authorization.UUID(installation) || len(validation.IsDNS1123Subdomain(name)) != 0 || plan == (artifact.Digest{}) {
		return nil, cfg.ErrInvalid
	}
	g, err := NewInitialWorkloadProtection(administrator, probe, workload, pin)
	if err != nil {
		return nil, err
	}
	return &InitialCredentialStateStore{g, inputUID, installation, name, plan}, nil
}
