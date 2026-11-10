package bootstrap

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/privacy"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
)

// Adapt the browser request-identity port to the privacy service's local port.
type publicProcessingInventory struct {
	privacy.ProcessingRuleInventory
}

func (s publicProcessingInventory) List(ctx context.Context, current identities.CurrentIdentity, q value.ProcessingInventoryQuery) (value.ProcessingInventoryPage, error) {
	return s.ProcessingRuleInventory.List(ctx, current, q)
}
