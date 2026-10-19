package mtls

import (
	"context"
	"errors"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// ADR-209: at most ContextStartExchangesPerOwner exchanges to one owner; a
// further open is refused before any setup or I/O, another owner is not.
func TestContextStartClientBoundsExchangesPerOwner(t *testing.T) {
	owner := ownerBootstrapBinding(ownerOtherID)
	pool := value.OwnerPool{InstallationID: owner.InstallationID, ClusterID: owner.ClusterID, IssuerEpoch: owner.IssuerEpoch}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &ContextStartClient{root: ctx, cancel: cancel, pool: pool, now: time.Now, maximum: 16, active: map[*ContextStartExchange]struct{}{}}
	for n := 0; n < ContextStartExchangesPerOwner; n++ {
		c.active[&ContextStartExchange{owner: owner}] = struct{}{}
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	if _, err := c.open(call, owner, time.Now().Add(5*time.Second)); !errors.Is(err, value.ErrUnavailable) {
		t.Fatalf("exchange beyond the per-owner bound: %v", err)
	}
	if len(c.active) != ContextStartExchangesPerOwner {
		t.Fatal("refused open registered an exchange")
	}
}
