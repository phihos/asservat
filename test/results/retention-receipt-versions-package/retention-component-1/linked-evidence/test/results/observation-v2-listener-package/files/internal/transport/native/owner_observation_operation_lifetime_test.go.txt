package native

import (
	"sync"
	"testing"
	"time"
)

// V2 calls the unchanged nativeConn admission/release mechanism. Exercise the
// exact first-request/close race, including a close before purpose-slot install;
// Close must either prevent admission or join the admitted slot owner.
func TestOwnerObservationOperationFirstRequestCloseRace(t *testing.T) {
	for i := 0; i < 64; i++ {
		c, _ := lifetimeConnection(t, 30*time.Second)
		start := make(chan struct{})
		release := make(chan struct{})
		var releaseOnce sync.Once
		finish := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(finish)
		accepted := make(chan bool, 1)
		requestDone := make(chan struct{})
		slots := make(chan struct{}, 1)
		closed := make(chan struct{})
		t.Cleanup(func() {
			finish()
			for _, done := range []chan struct{}{requestDone, closed} {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("first request/close fixture did not join")
				}
			}
		})
		go func() {
			defer close(requestDone)
			<-start
			if !c.beginRequest() {
				accepted <- false
				return
			}
			slots <- struct{}{}
			c.mu.Lock()
			c.release = func() { <-slots }
			c.mu.Unlock()
			accepted <- true
			<-release
			close(c.handlerDone)
		}()
		go func() { <-start; _ = c.Close(); close(closed) }()
		close(start)
		select {
		case admitted := <-accepted:
			if admitted {
				select {
				case <-closed:
					t.Fatal("close released an admitted unfinished request")
				default:
				}
				if len(slots) != 1 {
					t.Fatal("admitted purpose lost its slot")
				}
			}
		case <-time.After(time.Second):
			t.Fatal("first request/close race did not settle")
		}
		finish()
		select {
		case <-requestDone:
		case <-time.After(time.Second):
			t.Fatal("request did not join")
		}
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("connection close did not join")
		}
		if len(slots) != 0 || c.beginRequest() {
			t.Fatal("closed original retained/re-admitted a purpose slot")
		}
	}
}
