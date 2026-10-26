package capture

import "testing"

// One capture goroutine per policy: a running policy is reported busy (its
// tick is skipped), another policy is not, and the join waits for both.
func TestTriggerRunnerBoundsAndJoinsPolicyCaptures(t *testing.T) {
	r := &triggerRunner{busy: map[string]bool{}}
	release := make(chan struct{})
	done := 0
	r.start("a", func() { <-release; done++ })
	if !r.running("a") || r.running("b") {
		t.Fatal("busy state", r.running("a"), r.running("b"))
	}
	close(release)
	r.wg.Wait()
	if r.running("a") || done != 1 {
		t.Fatal("finished capture still busy or not joined", done)
	}
}
