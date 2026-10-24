package bootstrap

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	eventLogKeyLimit     = 128
	eventLogKeyBytes     = 256
	eventLogPayloadBytes = 4096
)

// eventLog writes each closed diagnostic event at its 1st, 2nd, 4th, 8th...
// occurrence with its count, so a burst shows its size in a few lines and
// interleaved events cannot flood the log. Callers pass closed event words only;
// the logger independently caps retained keys and never retains payloads.
func eventLog(out io.Writer, prefix string) func(string) {
	log := timedEventLog(out, prefix)
	return func(event string) { log(event, "") }
}

// Timing text is output only on the stable event's doubling sequence. It must
// contain only producer-owned stage names/numbers, never dependency error text.
func timedEventLog(out io.Writer, prefix string) func(string, string) {
	log := &eventLogger{out: out, prefix: prefix, counts: make(map[string]uint64)}
	return log.write
}

type eventLogger struct {
	mu       sync.Mutex
	out      io.Writer
	prefix   string
	counts   map[string]uint64
	overflow uint64
}

func (l *eventLogger) write(event, payload string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	valid := event != "" && event != "overflow" && eventLogText(event, eventLogKeyBytes)
	var n uint64
	var known bool
	if valid {
		n, known = l.counts[event]
	}
	overflow := !valid || (!known && len(l.counts) >= eventLogKeyLimit)
	if overflow {
		event, payload, n = "overflow", "", l.overflow
	}
	// Saturation must not wrap to zero and reopen the logging sequence.
	if n == ^uint64(0) {
		return
	}
	n++
	if overflow {
		l.overflow = n
	} else {
		// Map assignment may replace an equal string key's backing storage.
		// Clone on updates too, so a small slice cannot retain a large string.
		event = strings.Clone(event)
		l.counts[event] = n
	}
	if n&(n-1) != 0 {
		return
	}
	if !eventLogText(payload, eventLogPayloadBytes) {
		payload = ""
	}
	if payload != "" {
		payload = ", " + payload
	}
	fmt.Fprintf(l.out, "%s: %s (%d)%s\n", l.prefix, event, n, payload)
}

func eventLogText(s string, maximum int) bool {
	if len(s) > maximum {
		return false
	}
	for i := range len(s) {
		if s[i] < ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}
