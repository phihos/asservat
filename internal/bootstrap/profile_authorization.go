package bootstrap

import (
	"context"

	"asservat.local/asservat/internal/domain/planning"
)

// ProfileAuthorizationReader reads only the selected protected credential
// policy. The caller owns the admitted workload audience and original cutoff.
type ProfileAuthorizationReader interface {
	ReadProfileAuthorization(context.Context, planning.GoEndpointSource) ([]byte, error)
}

func (h *ConnectorRecordings) SetProfileAuthorizationReader(reader ProfileAuthorizationReader) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.profileAuthorization = reader
}
