package integration

import (
	"context"
	"sync"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
)

// memoryAuditEvents records the public wrapper's call rows in memory for
// suites whose subject is not audit storage.
type memoryAuditEvents struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *memoryAuditEvents) Record(_ context.Context, e audit.Event) error {
	if !e.Valid() {
		return auditapp.ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}
