package evidence

import (
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"time"
)

// A provider refresh is an explicit POST-admitted task. Its exact association
// can pause an existing GET, never create authority or renew a delivery frame.
// One settled claim permits one ordinary BeginBatch attempt. A repeated Busy
// cannot reset this budget or turn an unrelated session refresh into a retry.
func (c *responseCurrent) begin(ctx context.Context) (identities.IdentityBatch, error) {
	batch, err := c.reader.BeginBatch(ctx)
	if !errors.Is(err, value.ErrSessionBusy) || !c.response.Valid() {
		return batch, err
	}
	reader, ok := c.reader.(identities.PausingReader)
	if !ok {
		return nil, err
	}
	started := c.now()
	pending, stop := context.WithDeadline(ctx, started.Add(value.RefreshClaimWindow))
	defer stop()
	pause, e := reader.OwnedRefreshPause(pending, c.response)
	if e != nil || pending.Err() != nil || !pause.Valid(c.now()) || !pause.Matches(c.response) {
		return nil, value.ErrSessionBusy
	}
	if c.pauseUsed && c.lastPause.Owner == pause.Owner && c.lastPause.CredentialVersion == pause.CredentialVersion && c.lastPause.ClaimUntil.Equal(pause.ClaimUntil) {
		return nil, value.ErrSessionBusy
	}
	c.pauseUsed = true
	c.lastPause = pause
	pending, end := context.WithDeadline(pending, pause.ClaimUntil)
	defer end()
	for count := 0; !pause.Settled; count++ {
		if count >= 100 {
			return nil, value.ErrSessionBusy
		}
		wait := time.NewTimer(100 * time.Millisecond)
		select {
		case <-pending.Done():
			if !wait.Stop() {
				<-wait.C
			}
			return nil, value.ErrSessionBusy
		case <-wait.C:
		}
		next, e := reader.OwnedRefreshPause(pending, c.response)
		if e != nil || pending.Err() != nil || !next.Valid(c.now()) || !next.Matches(c.response) || next.Owner != pause.Owner || next.CredentialVersion != pause.CredentialVersion || !next.ClaimUntil.Equal(pause.ClaimUntil) {
			return nil, value.ErrSessionBusy
		}
		pause = next
	}
	if pending.Err() != nil || !c.now().Before(pause.ClaimUntil) {
		return nil, value.ErrSessionBusy
	}
	// The refreshed groups and original session end come from this new identity;
	// nothing from RefreshPause is copied into an authorization observation.
	return c.reader.BeginBatch(ctx)
}
