package kubernetes

import (
	"asservat.local/asservat/internal/domain/artifact"
)

// InitialCredentialStateStore is a trusted provisioning facet, not the
// activation Pod's client. It cannot create a namespace, guard, account or Pod.
// The independently pinned clean namespace must already have been established.
type InitialCredentialStateStore struct {
	protection                   *InitialWorkloadProtection
	inputUID, installation, name string
	plan                         artifact.Digest
}
