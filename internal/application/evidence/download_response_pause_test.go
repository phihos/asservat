package evidence

import (
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"testing"
	"time"
)

type responsePauseFixture struct {
	*responseTransferFixture
	attempts, observations int
	mode                   string
	pause                  value.RefreshPause
}

func (f *responsePauseFixture) BeginBatch(ctx context.Context) (identities.IdentityBatch, error) {
	f.attempts++
	if f.attempts == 1 || f.mode == "repeat-busy" {
		return nil, value.ErrSessionBusy
	}
	return f.responseTransferFixture.BeginBatch(ctx)
}
func (f *responsePauseFixture) OwnedRefreshPause(ctx context.Context, b value.RefreshResponseBinding) (value.RefreshPause, error) {
	f.observations++
	p := f.pause
	switch f.mode {
	case "mismatch":
		p.ResponseGeneration++
	case "expired":
		p.ClaimUntil = f.now
	case "nonjoined":
		return p, value.ErrUnavailable
	case "changed-claim":
		if f.observations > 1 {
			p.CredentialVersion++
		}
	case "pending":
		p.Settled = f.observations > 1
	case "cancel":
		<-ctx.Done()
		return p, ctx.Err()
	default:
		p.Settled = true
	}
	return p, nil
}
func pauseCurrentFixture(t *testing.T, mode string) (*responsePauseFixture, *responseCurrent) {
	f, _, _ := newResponseTransferFixture(t, 1)
	id := f.s.ID
	r := value.RefreshResponseBinding{DownloadID: id, ResponseID: id, ResponseOwnerID: id, ResponseGeneration: 1}
	p := value.RefreshPause{Owner: value.RefreshOwnerRef{RootID: id, Epoch: id, OwnerID: id, InstallationID: id, ClusterID: id, PodUID: id, ProcessEpoch: id, SessionID: [32]byte{1}, Generation: 1}, DownloadID: id, ResponseID: id, ResponseOwnerID: id, ResponseGeneration: 1, CredentialVersion: 1, ObservedAt: f.now, ValidUntil: f.now.Add(time.Second), ClaimUntil: f.now.Add(time.Second)}
	reader := &responsePauseFixture{responseTransferFixture: f, mode: mode, pause: p}
	return reader, &responseCurrent{reader: reader, authority: f, scope: f.s.Scope, now: func() time.Time { return f.now }, response: r}
}
func TestNativeResponseOwnedRefreshPauseSettledAndPending(t *testing.T) {
	for _, mode := range []string{"settled", "pending"} {
		t.Run(mode, func(t *testing.T) {
			f, c := pauseCurrentFixture(t, mode)
			b, e := c.begin(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer b.Close()
			if _, e = b.ResolveIdentity(context.Background()); e != nil {
				t.Fatal("new batch was cancelled with pause context", e)
			}
			if f.attempts != 2 || f.emitted != 0 || f.begins != 0 || f.leases != 0 {
				t.Fatal("pause retried work or emitted bytes")
			}
			if mode == "pending" && f.observations != 2 {
				t.Fatal("did not wait for original claim", f.observations)
			}
		})
	}
}
func TestNativeResponsePauseMismatchExpiryAndRepeatedBusyStop(t *testing.T) {
	for _, mode := range []string{"mismatch", "expired", "nonjoined", "repeat-busy", "changed-claim"} {
		t.Run(mode, func(t *testing.T) {
			f, c := pauseCurrentFixture(t, mode)
			if mode == "changed-claim" {
				f.pause.Settled = false
			}
			if b, e := c.begin(context.Background()); !errors.Is(e, value.ErrSessionBusy) || b != nil {
				t.Fatal("unqualified pause succeeded", e)
			}
			if f.attempts > 2 || f.emitted != 0 || f.begins != 0 || f.leases != 0 {
				t.Fatal("unbounded retry/effect")
			}
		})
	}
}
func TestNativeResponsePauseRequiresAdmittedResponseAndHonorsDisconnect(t *testing.T) {
	f, c := pauseCurrentFixture(t, "settled")
	c.response = value.RefreshResponseBinding{}
	if _, e := c.begin(context.Background()); !errors.Is(e, value.ErrSessionBusy) || f.observations != 0 {
		t.Fatal("pre-admission pause")
	}
	f, c = pauseCurrentFixture(t, "cancel")
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if _, e := c.begin(ctx); !errors.Is(e, value.ErrSessionBusy) || f.attempts != 1 {
		t.Fatal("disconnected pause restarted identity")
	}
}
