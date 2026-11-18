package mtls

import (
	"context"
	"errors"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

func TestContextStartClientBoundsConcurrentExchanges(t *testing.T) {
	owner := ownerBootstrapBinding(ownerOtherID)
	pool := value.OwnerPool{InstallationID: owner.InstallationID, ClusterID: owner.ClusterID, IssuerEpoch: owner.IssuerEpoch}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &ContextStartClient{root: ctx, cancel: cancel, pool: pool, now: time.Now, maximum: 4, active: map[*ContextStartExchange]struct{}{}}
	for n := 0; n < c.maximum; n++ {
		c.active[&ContextStartExchange{}] = struct{}{}
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	if _, err := c.OpenRequested(call, owner, time.Now().Add(5*time.Second)); !errors.Is(err, value.ErrUnavailable) {
		t.Fatalf("exchange beyond the connector concurrency: %v", err)
	}
	if len(c.active) != c.maximum {
		t.Fatal("refused open registered an exchange")
	}
}
