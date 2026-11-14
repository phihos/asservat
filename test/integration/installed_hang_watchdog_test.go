package integration

import (
	"fmt"
	"io"
	"runtime/pprof"
	"time"
)

// installedFailureGrace is how long a failed installed test may keep running
// (normally its cleanup) before the watchdog dumps every goroutine.
const installedFailureGrace = 90 * time.Second

// installedContinuationBudget is the soft budget of the installer-continuation
// subtest (bootstrap ends before it; the focus runs inside it) per
// ASSERVAT_JOURNEY_FOCUS. Values are about 1.5 times the subtest's normal
// duration, estimated from passing native.yml jobs (job total minus about
// 9.5 minutes of runner setup, fixture setup and bootstrap; the live focus
// measured 346 s of a 920 s job). Past it the watchdog dumps the goroutines
// once even if nothing failed, so a wait without a bound is visible while the
// job still runs. Unlisted feature focuses use the default.
var installedContinuationBudget = map[string]time.Duration{
	"":                   40 * time.Minute, // unsplit local run
	"manual-profile":     15 * time.Minute, // jobs up to 1196 s
	"manual-mixed":       15 * time.Minute, // 1180 s
	"manual-syscall":     15 * time.Minute, // 1170 s
	"manual-raw":         14 * time.Minute, // 1130 s
	"profile-comparison": 14 * time.Minute, // up to 1110 s
	// Full-chain and console focuses are sized for about 15-minute runs.
	"chain": 14 * time.Minute, "journey": 14 * time.Minute, "browser": 14 * time.Minute,
	"restart": 14 * time.Minute, "clusters": 14 * time.Minute, "upgrade": 14 * time.Minute,
	"policy": 14 * time.Minute, "alert": 14 * time.Minute, "share": 14 * time.Minute,
	"logresource": 14 * time.Minute,
}

// installedContinuationDefaultBudget covers the feature focuses whose jobs
// pass in 14-17 minutes (subtest about 5-7 minutes).
const installedContinuationDefaultBudget = 11 * time.Minute

func installedContinuationSoftBudget(focus string) time.Duration {
	if budget, ok := installedContinuationBudget[focus]; ok {
		return budget
	}
	return installedContinuationDefaultBudget
}

// installedContinuationBeforeFocus is the part of each focus' budget spent in
// the continuation before the focus starts (measured 175 s on 2026-11-08,
// about 1.4 times that). A multi-focus run pays it once.
const installedContinuationBeforeFocus = 4 * time.Minute

// startHangWatchdog polls failed every tick and writes one goroutine dump per
// reason (failure grace exceeded, soft budget exceeded) to out. stop ends the
// watch and waits for the poller to return.
func startHangWatchdog(failed func() bool, label string, grace, budget, tick time.Duration, out io.Writer) (stop func()) {
	done, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		started := time.Now()
		var failedAt time.Time
		dumpedFailure, dumpedBudget := false, false
		for !dumpedFailure || !dumpedBudget {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				if failedAt.IsZero() && failed() {
					failedAt = now
				}
				if !dumpedFailure && !failedAt.IsZero() && now.Sub(failedAt) >= grace {
					dumpedFailure = true
					writeHangDump(out, fmt.Sprintf("%s failed %s ago and is still running", label, now.Sub(failedAt).Round(time.Second)))
				}
				if !dumpedBudget && now.Sub(started) >= budget {
					dumpedBudget = true
					writeHangDump(out, fmt.Sprintf("%s still running past its %s soft budget", label, budget))
				}
			}
		}
	}()
	return func() {
		select {
		case <-done:
		default:
			close(done)
		}
		<-exited // the poller never blocks: it returns at the next select
	}
}

func writeHangDump(out io.Writer, reason string) {
	fmt.Fprintf(out, "installed hang watchdog: %s; goroutines:\n", reason)
	_ = pprof.Lookup("goroutine").WriteTo(out, 2)
	fmt.Fprintln(out, "installed hang watchdog: end of goroutine dump")
}
