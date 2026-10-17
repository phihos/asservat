package bootstrap

import (
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/contracts"
	"net/http"
)

// Every accepted installer format requires immutable audit versions before an
// effect can produce a receipt. Retaining a legacy input never selects a weaker
// active backend; its historical bytes and acknowledgements stay unchanged.
// A missing returned version cannot select a weaker backend or another attempt.
func (in *initialInputs) auditStore(h *http.Client) (*objectstore.Store, error) {
	if in == nil || in.providerInputs == nil {
		return nil, mounts.ErrUnavailable
	}
	c := in.config
	switch c.Format {
	case contracts.InitialInstallerVersionedAuditFormat, contracts.InitialInstallerFormat:
		return objectstore.NewVersionedAudit(c.AuditStore.Endpoint, c.AuditStore.Region, c.AuditStore.Bucket, mountedStorage{in.providerInputs}, h)
	default:
		return nil, mounts.ErrUnavailable
	}
}
