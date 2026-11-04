//go:build ignore

// Synthetic workload for native profile qualification. Never shipped in the product image.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	httppprof "net/http/pprof"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var observed atomic.Uint64
var retained [][]byte

//go:noinline
func burnCPU() {
	var n uint64 = 1
	for i := 0; i < 100000; i++ {
		n = n*1664525 + 1013904223
	}
	observed.Store(n)
}
func main() {
	for i := 0; i < 128; i++ {
		retained = append(retained, make([]byte, 32<<10))
	}
	runtime.GC() // fixture setup gives snapshot heap profiling a retained baseline
	go func() {
		for {
			burnCPU()
			runtime.Gosched()
		}
	}()
	profiles := http.NewServeMux()
	profiles.Handle("/debug/pprof/", http.DefaultServeMux)
	var missing atomic.Bool
	var requests atomic.Int64
	profiles.HandleFunc("/debug/pprof/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			requests.Add(1)
		}
		if missing.Load() {
			http.NotFound(w, r)
			return
		}
		httppprof.Profile(w, r)
	})
	workload := http.NewServeMux()
	workload.Handle("/", profiles)
	workload.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("synthetic profile workload\n")) })
	// Test-owner controls exist only in this synthetic workload, on its existing
	// health listener. Product acquisition never calls these paths or stops a
	// profiler: it retains the fixed /debug/pprof allowlist.
	var ownerMu sync.Mutex
	ownerRunning := false
	workload.HandleFunc("POST /fixture/profile-mode", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 8))
		if err != nil || string(body) != "normal" && string(body) != "missing" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		missing.Store(string(body) == "missing")
		w.WriteHeader(http.StatusNoContent)
	})
	workload.HandleFunc("POST /fixture/cpu-profiler/start", func(w http.ResponseWriter, _ *http.Request) {
		ownerMu.Lock()
		defer ownerMu.Unlock()
		if ownerRunning || pprof.StartCPUProfile(io.Discard) != nil {
			w.WriteHeader(http.StatusConflict)
			return
		}
		ownerRunning = true
		w.WriteHeader(http.StatusNoContent)
	})
	workload.HandleFunc("POST /fixture/cpu-profiler/stop", func(w http.ResponseWriter, _ *http.Request) {
		ownerMu.Lock()
		defer ownerMu.Unlock()
		if ownerRunning {
			pprof.StopCPUProfile()
			ownerRunning = false
		}
		w.WriteHeader(http.StatusNoContent)
	})
	workload.HandleFunc("GET /fixture/cpu-profiler", func(w http.ResponseWriter, _ *http.Request) {
		ownerMu.Lock()
		defer ownerMu.Unlock()
		busy := false
		if ownerRunning {
			if pprof.StartCPUProfile(io.Discard) != nil {
				busy = true
			} else {
				pprof.StopCPUProfile()
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			OwnerRunning    bool  `json:"owner_running"`
			RuntimeBusy     bool  `json:"runtime_busy"`
			ProfileRequests int64 `json:"profile_requests"`
		}{ownerRunning, busy, requests.Load()})
	})
	redirect := http.NewServeMux()
	redirect.HandleFunc("/debug/pprof/profile", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:6060/debug/pprof/profile?seconds=1", http.StatusFound)
	})
	// Deliberately malformed trace-sized input for acquisition-buffer testing.
	// It has a recognized header but invalid events and must never pass parsing.
	large := http.NewServeMux()
	large.HandleFunc("/debug/pprof/trace", func(w http.ResponseWriter, r *http.Request) {
		const size = 128 << 20
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(size))
		header := []byte("go 1.23 trace\x00\x00\x00")
		if _, err := w.Write(header); err != nil {
			return
		}
		_, _ = io.CopyN(w, zeroReader{}, size-int64(len(header)))
	})
	go func() {
		log.Fatal((&http.Server{Addr: "127.0.0.1:6071", Handler: large, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
	}()
	go func() {
		log.Fatal((&http.Server{Addr: "127.0.0.1:6070", Handler: redirect, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
	}()
	go func() {
		log.Fatal((&http.Server{Addr: "127.0.0.1:6060", Handler: profiles, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
	}()
	log.Fatal((&http.Server{Addr: ":8080", Handler: workload, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }
