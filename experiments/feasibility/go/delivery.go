package feasibility

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// Grant is an in-memory test authority, NOT Asservat's SQL/OIDC/grant implementation.
type Grant struct {
	mu                  sync.Mutex
	Remaining, Spent    int64
	Revoked             bool
	Expires             time.Time
	MaxBatches, Batches int
}

func (g *Grant) allow(n int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.Revoked || !time.Now().Before(g.Expires) || g.Remaining < int64(n) || (n > 0 && g.MaxBatches > 0 && g.Batches >= g.MaxBatches) {
		return false
	}
	if n > 0 {
		g.Remaining -= int64(n)
		g.Spent += int64(n)
		g.Batches++
	}
	return true
}

var rangePattern = regexp.MustCompile(`^bytes=([0-9]+)-([0-9]*)$`)

func nativeRange(value string, size int64) (int64, int64, error) {
	if value == "" {
		return 0, size, nil
	}
	m := rangePattern.FindStringSubmatch(value)
	if m == nil {
		return 0, 0, fmt.Errorf("one explicit range required")
	}
	lo, e := strconv.ParseInt(m[1], 10, 64)
	if e != nil || lo >= size {
		return 0, 0, fmt.Errorf("range start")
	}
	hi := size - 1
	if m[2] != "" {
		hi, e = strconv.ParseInt(m[2], 10, 64)
		if e != nil {
			return 0, 0, e
		}
	}
	if hi < lo || hi >= size {
		return 0, 0, fmt.Errorf("range end")
	}
	return lo, hi + 1, nil
}
func Handler(store *Store, b Bundle, g *Grant) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method", 405)
			return
		}
		if r.Header.Get("Authorization") != "Bearer synthetic-human" || !g.allow(0) {
			http.Error(w, "denied", 403)
			return
		}
		if tag := r.Header.Get("If-Range"); tag != "" && tag != `"`+b.IndexSHA+`"` {
			http.Error(w, "version changed", 412)
			return
		}
		idx, e := store.Open(r.Context(), b)
		if e != nil {
			http.Error(w, "unavailable", 502)
			return
		}
		lo, hi, e := nativeRange(r.Header.Get("Range"), idx.NativeBytes)
		if e != nil {
			http.Error(w, "invalid range", 416)
			return
		}
		h := w.Header()
		h.Set("Cache-Control", "no-store, private")
		h.Set("Content-Type", "application/octet-stream")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Disposition", `attachment; filename="synthetic-evidence.bin"`)
		h.Set("ETag", `"`+b.IndexSHA+`"`)
		h.Set("Accept-Ranges", "bytes")
		h.Set("Content-Length", strconv.FormatInt(hi-lo, 10))
		status := 200
		if r.Header.Get("Range") != "" {
			status = 206
			h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", lo, hi-1, idx.NativeBytes))
		}
		w.WriteHeader(status)
		if e = store.Range(r.Context(), b, idx, lo, hi, w, g.allow); e != nil {
			panic(http.ErrAbortHandler)
		}
	})
}
func cancelled() context.Context { ctx, c := context.WithCancel(context.Background()); c(); return ctx }
