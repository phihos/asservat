package native

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

type deadlineRecorder struct {
	net.Conn
	mu  sync.Mutex
	end time.Time
}

func (c *deadlineRecorder) SetDeadline(v time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.end = v
	return nil
}
func (c *deadlineRecorder) SetReadDeadline(v time.Time) error  { return c.SetDeadline(v) }
func (c *deadlineRecorder) SetWriteDeadline(v time.Time) error { return c.SetDeadline(v) }
func (c *deadlineRecorder) deadline() time.Time                { c.mu.Lock(); defer c.mu.Unlock(); return c.end }
func lifetimeConnection(t *testing.T, lifetime time.Duration) (*nativeConn, *deadlineRecorder) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	n := time.Now()
	ctx, stop := context.WithDeadline(context.Background(), n.Add(lifetime))
	raw := &deadlineRecorder{Conn: a}
	c := &nativeConn{Conn: raw, ctx: ctx, cancel: stop, accepted: n, until: n.Add(lifetime), callback: make(chan struct{}), handlerDone: make(chan struct{})}
	c.stop = context.AfterFunc(ctx, func() { raw.Close(); close(c.callback) })
	t.Cleanup(func() {
		if c.request.Load() {
			select {
			case <-c.handlerDone:
			default:
				close(c.handlerDone)
			}
		}
		c.Close()
	})
	return c, raw
}
func TestNativePurposeOriginalAcceptedDeadlineCannotRenew(t *testing.T) {
	for _, lifetime := range []time.Duration{10 * time.Second, 30 * time.Second} {
		t.Run(lifetime.String(), func(t *testing.T) {
			c, raw := lifetimeConnection(t, 30*time.Second)
			want := c.accepted.Add(lifetime)
			if e := c.shorten(want); e != nil {
				t.Fatal(e)
			}
			for _, v := range []time.Time{{}, want.Add(time.Hour)} {
				for _, set := range []func(time.Time) error{c.SetDeadline, c.SetReadDeadline, c.SetWriteDeadline} {
					if e := set(v); e != nil || !raw.deadline().Equal(want) {
						t.Fatal("socket deadline exceeded original accepted bound", e)
					}
				}
			}
			earlier := want.Add(-time.Second)
			if e := c.shorten(earlier); e != nil {
				t.Fatal(e)
			}
			if e := c.shorten(want); e != nil || !raw.deadline().Equal(earlier) {
				t.Fatal("later purpose/handshake extended shortened bound", e)
			}
		})
	}
}
func TestNativePurposeClosingRetainsReservationUntilHandlerJoin(t *testing.T) {
	c, _ := lifetimeConnection(t, 30*time.Second)
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	if !c.beginRequest() {
		t.Fatal("original request refused")
	}
	c.mu.Lock()
	c.release = func() { <-slots }
	c.mu.Unlock()
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	<-c.ctx.Done()
	if c.beginRequest() {
		t.Fatal("closing original socket admitted another request")
	}
	select {
	case <-done:
		t.Fatal("close returned before joined handler")
	default:
	}
	select {
	case slots <- struct{}{}:
		t.Fatal("closing purpose slot was prematurely reused")
	default:
	}
	close(c.handlerDone)
	<-done
	if len(slots) != 0 {
		t.Fatal("joined purpose slot did not release")
	}
	if c.beginRequest() {
		t.Fatal("closed socket admitted another conversation")
	}
}
func TestNativePurposeCloseBeforeFirstRequestCannotStrandSlot(t *testing.T) {
	c, _ := lifetimeConnection(t, 30*time.Second)
	if e := c.Close(); e != nil {
		t.Fatal(e)
	}
	if c.beginRequest() {
		t.Fatal("completed socket close raced into a later handler")
	}
}
