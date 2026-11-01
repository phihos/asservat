package kubernetes

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/client-go/util/flowcontrol"
)

// openingStats counts the process's opening-client Kubernetes traffic for a
// diagnostic summary: request round trips and ADR-208 limiter waits. It holds
// no identifiers, paths or bodies.
var openingStats struct {
	requests, slow1, slow2, failed       atomic.Int64
	waits, refused, waitNanos, maxWaitNs atomic.Int64
	mu                                   sync.Mutex
	kinds                                map[string]int64
}

// requestKind is the request's verb and resource kind (with subresource),
// e.g. "GET pods", "POST tokenreviews"; names, namespaces and bodies are
// dropped.
func requestKind(r *http.Request) string {
	if r.URL == nil {
		return r.Method + " other"
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case len(parts) >= 2 && parts[0] == "api":
		parts = parts[2:]
	case len(parts) >= 3 && parts[0] == "apis":
		parts = parts[3:]
	default:
		return r.Method + " other"
	}
	if len(parts) >= 3 && parts[0] == "namespaces" {
		parts = parts[2:]
	}
	if len(parts) == 0 {
		return r.Method + " other"
	}
	kind := parts[0]
	if len(parts) >= 3 {
		kind += "/" + parts[2]
	}
	return r.Method + " " + kind
}

type measuredLimiter struct{ flowcontrol.RateLimiter }

func (m measuredLimiter) Wait(ctx context.Context) error {
	start := time.Now()
	err := m.RateLimiter.Wait(ctx)
	d := time.Since(start)
	if err != nil {
		openingStats.refused.Add(1)
	}
	if d >= 100*time.Millisecond {
		openingStats.waits.Add(1)
		openingStats.waitNanos.Add(int64(d))
		for {
			old := openingStats.maxWaitNs.Load()
			if int64(d) <= old || openingStats.maxWaitNs.CompareAndSwap(old, int64(d)) {
				break
			}
		}
	}
	return err
}

type measuredTransport struct{ next http.RoundTripper }

func (m measuredTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := m.next.RoundTrip(r)
	d := time.Since(start)
	openingStats.requests.Add(1)
	k := requestKind(r)
	openingStats.mu.Lock()
	if openingStats.kinds == nil {
		openingStats.kinds = map[string]int64{}
	}
	if len(openingStats.kinds) < 64 || openingStats.kinds[k] > 0 {
		openingStats.kinds[k]++
	}
	openingStats.mu.Unlock()
	if err != nil {
		openingStats.failed.Add(1)
	}
	if d >= time.Second {
		openingStats.slow1.Add(1)
	}
	if d >= 2*time.Second {
		openingStats.slow2.Add(1)
	}
	return resp, err
}

// OpeningStatsLine summarizes the counters since the last call and resets
// them; it returns "" without traffic.
func OpeningStatsLine() string {
	n := openingStats.requests.Swap(0)
	waits := openingStats.waits.Swap(0)
	if n == 0 && waits == 0 {
		return ""
	}
	slow1, slow2, failed := openingStats.slow1.Swap(0), openingStats.slow2.Swap(0), openingStats.failed.Swap(0)
	refused, total, max := openingStats.refused.Swap(0), openingStats.waitNanos.Swap(0), openingStats.maxWaitNs.Swap(0)
	openingStats.mu.Lock()
	kinds := openingStats.kinds
	openingStats.kinds = nil
	openingStats.mu.Unlock()
	type kc struct {
		k string
		n int64
	}
	top := make([]kc, 0, len(kinds))
	for k, c := range kinds {
		top = append(top, kc{k, c})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].n > top[j].n })
	var b strings.Builder
	for i, t := range top {
		if i == 6 {
			break
		}
		fmt.Fprintf(&b, " [%s]=%d", t.k, t.n)
	}
	return fmt.Sprintf("requests=%d failed=%d slow>=1s=%d slow>=2s=%d limiter-waits>=100ms=%d wait-total=%s wait-max=%s limiter-refused=%d top:%s",
		n, failed, slow1, slow2, waits, time.Duration(total).Round(10*time.Millisecond), time.Duration(max).Round(10*time.Millisecond), refused, b.String())
}

var guardCallers struct {
	mu sync.Mutex
	n  map[string]int64
}

// countGuardCaller counts admission-guard checks by the code path (two
// calling function names) that made them; no data is recorded.
func countGuardCaller() {
	pcs := make([]uintptr, 3)
	n := runtime.Callers(3, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	var names []string
	for len(names) < 2 {
		f, more := frames.Next()
		name := f.Function
		if i := strings.LastIndex(name, "."); i >= 0 {
			name = name[i+1:]
		}
		names = append(names, name)
		if !more {
			break
		}
	}
	key := strings.Join(names, "<")
	guardCallers.mu.Lock()
	if guardCallers.n == nil {
		guardCallers.n = map[string]int64{}
	}
	if len(guardCallers.n) < 32 || guardCallers.n[key] > 0 {
		guardCallers.n[key]++
	}
	guardCallers.mu.Unlock()
}

// GuardCallersLine summarizes and resets the guard-check callers.
func GuardCallersLine() string {
	guardCallers.mu.Lock()
	m := guardCallers.n
	guardCallers.n = nil
	guardCallers.mu.Unlock()
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return m[keys[i]] > m[keys[j]] })
	var b strings.Builder
	for i, k := range keys {
		if i == 6 {
			break
		}
		fmt.Fprintf(&b, " [%s]=%d", k, m[k])
	}
	return "guard checks:" + b.String()
}
