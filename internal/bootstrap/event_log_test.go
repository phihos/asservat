package bootstrap

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestEventLogDoublesPerEvent(t *testing.T) {
	var out bytes.Buffer
	log := eventLog(&out, "x")
	for range 5 {
		log("a")
		log("b")
	}
	want := "x: a (1)\nx: b (1)\nx: a (2)\nx: b (2)\nx: a (4)\nx: b (4)\n"
	if out.String() != want {
		t.Fatalf("%q", out.String())
	}
}

func TestEventLogConcurrentCountsAndSaturation(t *testing.T) {
	var out bytes.Buffer
	log := &eventLogger{out: &out, prefix: "x", counts: make(map[string]uint64)}
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() {
			for range 32 {
				log.write("ok", "q-source=10ms")
			}
		})
	}
	group.Wait()
	if len(log.counts) != 1 || log.counts["ok"] != 1024 || strings.Count(out.String(), "\n") != 11 {
		t.Fatal("concurrent diagnostic counts were lost or bypassed suppression")
	}
	out.Reset()
	log.counts["ok"], log.overflow = ^uint64(0)-1, ^uint64(0)-1
	for range 3 {
		log.write("ok", "")
		log.write("overflow", "")
	}
	if log.counts["ok"] != ^uint64(0) || log.overflow != ^uint64(0) || out.Len() != 0 {
		t.Fatal("saturated diagnostic counter wrapped or reopened output")
	}
}

func TestRegionalTargetAnswerKeepsTimingOutsideEventKey(t *testing.T) {
	var out bytes.Buffer
	targets := reportedTargets{report: timedEventLog(&out, "regional target answer")}
	for n := 1; n <= 32; n++ {
		targets.ReportAnswer(fmt.Sprintf("r-resolve@<%dms", n*10))
	}
	if strings.Count(out.String(), "\n") != 6 || !strings.Contains(out.String(), "answer (32), r-resolve@<320ms") {
		t.Fatalf("regional answer timings changed suppression: %s", out.String())
	}
}

func TestEventLogTimingPayloadDoesNotChangeSuppressionKey(t *testing.T) {
	var out bytes.Buffer
	log := timedEventLog(&out, "target")
	for n := 1; n <= 32; n++ {
		log("ok", fmt.Sprintf("q-source=%dms q-check=%dms", n*10, n*20))
	}
	if strings.Count(out.String(), "\n") != 6 || !strings.Contains(out.String(), "ok (32)") || !strings.Contains(out.String(), "q-source=320ms") {
		t.Fatalf("changing timings bypassed event suppression: %s", out.String())
	}
}

func TestEventLogBoundsDistinctEventsAndRejectsUnboundedText(t *testing.T) {
	var out bytes.Buffer
	logger := &eventLogger{out: &out, prefix: "target", counts: make(map[string]uint64)}
	log := logger.write
	for n := range 1024 {
		log(fmt.Sprintf("event-%d", n), "q-source=10ms")
	}
	// At most 128 distinct retained events, then one shared doubling sequence.
	if len(logger.counts) != 128 || logger.overflow != 896 || strings.Count(out.String(), "\n") > 139 || strings.Contains(out.String(), "event-128 ") || !strings.Contains(out.String(), "overflow (512)") {
		t.Fatalf("event identities escaped the fixed bound: %d lines", strings.Count(out.String(), "\n"))
	}
	out.Reset()
	log = timedEventLog(&out, "target")
	log("private-token\ninjected", "q-source=10ms")
	log(strings.Repeat("private-token", 100), "q-source=10ms")
	log("ok", strings.Repeat("private-token", 1024))
	log("ok", "private-token\ninjected")
	if strings.Contains(out.String(), "private-") || strings.Contains(out.String(), "injected") || strings.Count(out.String(), "\n") != 4 {
		t.Fatalf("unbounded or multiline diagnostic text escaped: %q", out.String())
	}
}
