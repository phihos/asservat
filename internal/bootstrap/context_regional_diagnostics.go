package bootstrap

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// reportFailure never forwards arbitrary dependency error text or FixedStep
// values. Its finite vocabulary keeps eventLog's count map bounded as well as
// keeping private target, token, endpoint and provider details out of the log.
func (s RegionalContextStartConnections) reportFailure(stage string, cause error) {
	if s.Report == nil && s.ReportOpening == nil {
		return
	}
	switch stage {
	case "candidates", "candidates-empty", "open", "exchange":
	default:
		return
	}
	var fixed interface{ FixedStep() string }
	if errors.As(cause, &fixed) {
		switch step := fixed.FixedStep(); step {
		case "local", "route", "dial", "tls", "peer", "request", "response", "current",
			"discovery", "setup-begin", "process-open", "channel", "process-first", "owner-first", "source", "headers", "hello", "finish", "process-closing", "owner-closing", "process-final", "close",
			"setup-source-open", "setup-owned-process", "setup-process-proof", "setup-process-match", "setup-execution-account", "setup-settings-guard", "setup-settings-snapshot", "setup-workload", "setup-settings-guard-after", "setup-settings-snapshot-after", "setup-workload-guard-after", "setup-source-close", "setup-owned-process-after", "setup-fresh":
			stage += "/" + step
		}
	}
	if cause != nil {
		stage += " (" + regionalCause(cause) + ")"
	}
	var timed interface {
		OpeningTiming() (time.Duration, time.Duration)
	}
	if s.ReportOpening != nil && errors.As(cause, &timed) {
		elapsed, remaining := timed.OpeningTiming()
		if elapsed >= 0 && remaining >= 0 && remaining <= 5*time.Second {
			s.ReportOpening(stage, elapsed, remaining)
			return
		}
	}
	if s.Report != nil {
		s.Report(stage)
	}
}

// The event is already restricted by reportFailure. Durations never enter the
// count map: many differently timed refusals still share one bounded key.
func contextStartOpeningLog(out io.Writer) func(string, time.Duration, time.Duration) {
	var mu sync.Mutex
	counts := map[string]uint64{}
	return func(event string, elapsed, remaining time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		counts[event]++
		if n := counts[event]; n&(n-1) == 0 {
			fmt.Fprintf(out, "regional context standby refused: %s (%d), elapsed=%s remaining=%s\n", event, n, elapsed.Round(10*time.Millisecond), remaining.Round(10*time.Millisecond))
		}
	}
}
