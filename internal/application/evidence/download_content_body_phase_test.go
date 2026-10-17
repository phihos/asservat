package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

type contentBodyPhaseFixture struct {
	*contentAuditFixture
	calls    int
	until    time.Time
	failBody bool
}

func (f *contentBodyPhaseFixture) BeginDownloadContentBody(ctx context.Context, until time.Time) error {
	f.calls++
	f.until = until
	if f.finished != 1 || f.notified != 1 || f.status != DownloadContentReady || f.batches != 1 || f.begins != 0 || f.emitted != 0 {
		return errors.New("body setup outside acknowledged phase boundary")
	}
	if d, ok := ctx.Deadline(); !ok || until.After(d) || until.After(f.s.Deadline) || until.After(f.a.AccessUntil) {
		return errors.New("original response bounds lost")
	}
	if f.failBody {
		return artifact.ErrDownloadUnavailable
	}
	return nil
}
func TestNativeContentBodyPhaseAfterAuditBeforeFreshAuthority(t *testing.T) {
	for _, mode := range []string{"ready", "conditional", "finish-failed", "finish-shortened", "body-failed"} {
		t.Run(mode, func(t *testing.T) {
			base, transfer, request := newResponseTransferFixture(t, 17)
			request.HardUntil = base.now.Add(30 * time.Second)
			f := &contentBodyPhaseFixture{contentAuditFixture: &contentAuditFixture{responseTransferFixture: base, mode: mode}, failBody: mode == "body-failed"}
			if mode == "conditional" {
				f.condition = errors.New("not modified")
			}
			ctx, end := context.WithDeadline(t.Context(), base.now.Add(20*time.Second))
			defer end()
			e := transfer.TransferAudited(ctx, base, request, f, f, f)
			switch mode {
			case "ready", "finish-shortened":
				if e != nil || f.calls != 1 || f.batches != 2 || f.emitted != 17 {
					t.Fatalf("phase missing/out of order: %v calls=%d batches=%d bytes=%d", e, f.calls, f.batches, f.emitted)
				}
				want := base.now.Add(20 * time.Second)
				if mode == "finish-shortened" {
					want = f.a.AccessUntil
				}
				if !f.until.Equal(want) {
					t.Fatal("deadline changed", f.until, want)
				}
			case "body-failed":
				if e == nil || f.calls != 1 || f.batches != 1 || f.begins != 0 || f.emitted != 0 {
					t.Fatal("failed socket transition admitted body")
				}
			default:
				if e == nil || f.calls != 0 || f.begins != 0 || f.emitted != 0 {
					t.Fatal("failed/conditional preflight entered body phase")
				}
			}
		})
	}
}
