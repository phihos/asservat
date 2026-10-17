package evidence

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

func TestNativeTerminalSnapshotNeverRenewsOrConsultsRetiredAuthority(t *testing.T) {
	lease := nativeLeaseFixture()
	now := lease.ObservedAt
	var calls atomic.Int32
	g, e := NewNativeFrameGate(context.Background(), func(context.Context) (value.NativeLease, error) {
		if calls.Add(1) > 1 {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		return lease, nil
	}, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	now = now.Add(time.Second)
	got, e := g.TerminalLease(context.Background())
	if e != nil || got != lease || calls.Load() != 1 {
		t.Fatal("terminal snapshot changed original checked facts", got, e, calls.Load())
	}
	now = lease.Until
	if _, e = g.TerminalLease(context.Background()); e == nil {
		t.Fatal("expired original terminal lease returned")
	}
	if calls.Load() != 1 {
		t.Fatal("terminal snapshot renewed authority")
	}
}

func TestNativeTerminalSnapshotRejectsUnknownOrKnownLostAuthority(t *testing.T) {
	for _, mode := range []string{"zero", "nil", "cancelled-caller", "cancelled-owner", "known-revoked", "known-owner-change", "shortened"} {
		t.Run(mode, func(t *testing.T) {
			lease := nativeLeaseFixture()
			now := lease.ObservedAt
			owner, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			g, e := NewNativeFrameGate(owner, func(context.Context) (value.NativeLease, error) {
				l := lease
				if calls.Add(1) > 1 {
					switch mode {
					case "known-revoked":
						return value.NativeLease{}, artifact.ErrDownloadUnavailable
					case "known-owner-change":
						l.Operation.Reference.Fence++
					case "shortened":
						l.Until = now.Add(time.Second)
					}
				}
				return l, nil
			}, func() time.Time { return now })
			if e != nil {
				t.Fatal(e)
			}
			defer g.Close()
			ctx := context.Background()
			switch mode {
			case "zero":
				g = &NativeFrameGate{}
			case "nil":
				g = nil
			case "cancelled-caller":
				c, stop := context.WithCancel(ctx)
				stop()
				ctx = c
			case "cancelled-owner":
				cancel()
			case "known-revoked", "known-owner-change":
				if _, e = g.Check(ctx); e == nil {
					t.Fatal("current lost authority accepted")
				}
			case "shortened":
				short, e := g.Check(ctx)
				if e != nil {
					t.Fatal(e)
				}
				now = short.Until
			}
			if _, e = g.TerminalLease(ctx); e == nil {
				t.Fatal("terminal snapshot revived lost authority")
			}
		})
	}
}
