package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"testing"
)

type deliverySourceFixture struct {
	*responseTransferFixture
	ack       int
	uncertain bool
	pending   bool
}

func (f *deliverySourceFixture) ReadChunk(ctx context.Context, l artifact.DownloadDeliveryLease, o, n int64) (NativeResponseChunk, error) {
	c, e := f.responseTransferFixture.ReadChunk(ctx, l, o, n)
	if e == nil {
		f.pending = true
	}
	return c, e
}
func (f *deliverySourceFixture) AcknowledgeNativeChunk(ctx context.Context, l artifact.DownloadDeliveryLease, o, n int64) error {
	f.ack++
	if ctx.Err() != nil || !l.Allows(o, n, f.now) || n != f.emitted-o || f.chunks != f.ack || !f.pending {
		return artifact.ErrIntegrity
	}
	if f.uncertain {
		return artifact.ErrDownloadUnavailable
	}
	f.pending = false
	return nil
}
func (f *deliverySourceFixture) Close() {
	f.pending = false
	clear(f.backing)
	f.responseTransferFixture.Close()
}
func TestNativeDeliveryAckFollowsFinalSinkAndUnknownStaysSpent(t *testing.T) {
	for _, mode := range []string{"success", "partial-sink", "lost-ack"} {
		t.Run(mode, func(t *testing.T) {
			f, s, r := newResponseTransferFixture(t, 17)
			remote := &deliverySourceFixture{responseTransferFixture: f, uncertain: mode == "lost-ack"}
			if mode == "partial-sink" {
				f.fail = "write"
			}
			err := s.Transfer(context.Background(), f, r, remote, f)
			if mode == "success" {
				if err != nil || remote.ack != 1 || f.s.State != artifact.DownloadCompleted {
					t.Fatalf("success: %v ack=%d state=%s", err, remote.ack, f.s.State)
				}
			} else {
				if err == nil || f.s.State == artifact.DownloadCompleted || f.s.ChargedOutput != 17 || f.intents != 1 {
					t.Fatalf("uncertainty refunded/retried: %v %+v", err, f.s)
				}
				if mode == "partial-sink" && remote.ack != 0 {
					t.Fatal("partial sink acknowledged")
				}
				if mode == "lost-ack" && (remote.ack != 1 || f.s.EmittedBytes != 17) {
					t.Fatal("actual emitted bytes lost from failed outcome")
				}
			}
			if remote.pending {
				t.Fatal("pending remote chunk not joined on close")
			}
			for _, b := range f.backing {
				if b != 0 {
					t.Fatal("plaintext retained")
				}
			}
		})
	}
}
