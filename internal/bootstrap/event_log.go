package bootstrap

import (
	"fmt"
	"io"
	"sync"
)

// eventLog writes each closed diagnostic event at its 1st, 2nd, 4th, 8th...
// occurrence with its count, so a burst shows its size in a few lines and
// interleaved events cannot flood the log. Callers pass closed event words
// only, which keeps the counts bounded. Safe for concurrent use.
func eventLog(out io.Writer, prefix string) func(string) {
	var mu sync.Mutex
	counts := map[string]uint64{}
	return func(event string) {
		mu.Lock()
		defer mu.Unlock()
		counts[event]++
		if n := counts[event]; n&(n-1) == 0 {
			fmt.Fprintf(out, "%s: %s (%d)\n", prefix, event, n)
		}
	}
}
