//go:build ignore

// Synthetic workload for native profile qualification. Never shipped in the product image.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	httppprof "net/http/pprof"
	"net/url"
	"os"
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
	var heavy *acceptedHeavy
	var servingTLS *tls.Config
	if len(os.Args) > 1 && os.Args[1] == "--tls" {
		var err error
		servingTLS, err = profileWorkloadTLS(os.Args[1:])
		if err != nil {
			log.Fatal(err)
		}
	} else if len(os.Args) != 1 {
		if len(os.Args) != 2 || os.Args[1] != "--accepted-heavy" {
			log.Fatal("unknown synthetic profile workload mode")
		}
		var err error
		heavy, err = openAcceptedHeavy([2]string{"/profile-heavy-baseline.pb.gz", "/profile-heavy-incident.pb.gz"})
		if err != nil {
			log.Fatal(err)
		}
		defer heavy.Close()
	}
	if heavy == nil {
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
	}
	profiles := http.NewServeMux()
	profiles.Handle("/debug/pprof/", http.DefaultServeMux)
	var missing atomic.Bool
	var requests atomic.Int64
	profiles.HandleFunc("/debug/pprof/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			requests.Add(1)
		}
		if heavy != nil {
			heavy.ServeHTTP(w, r)
			return
		}
		if missing.Load() {
			http.NotFound(w, r)
			return
		}
		httppprof.Profile(w, r)
	})
	workload := http.NewServeMux()
	if servingTLS == nil {
		workload.Handle("/", profiles)
	}
	workload.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("synthetic profile workload\n")) })
	// Test-owner controls exist only in this synthetic workload, on its existing
	// health listener. Product acquisition never calls these paths or stops a
	// profiler: it retains the fixed /debug/pprof allowlist.
	var ownerMu sync.Mutex
	ownerRunning := false
	workload.HandleFunc("POST /fixture/profile-mode", func(w http.ResponseWriter, r *http.Request) {
		if heavy != nil {
			w.WriteHeader(http.StatusConflict)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8))
		if err != nil || string(body) != "normal" && string(body) != "missing" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		missing.Store(string(body) == "missing")
		w.WriteHeader(http.StatusNoContent)
	})
	workload.HandleFunc("POST /fixture/cpu-profiler/start", func(w http.ResponseWriter, _ *http.Request) {
		if heavy != nil {
			w.WriteHeader(http.StatusConflict)
			return
		}
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
		server := &http.Server{Addr: "127.0.0.1:6060", Handler: profiles, ReadHeaderTimeout: 5 * time.Second, TLSConfig: servingTLS}
		if servingTLS != nil {
			log.Fatal(server.ListenAndServeTLS("", ""))
		}
		log.Fatal(server.ListenAndServe())
	}()
	log.Fatal((&http.Server{Addr: ":8080", Handler: workload, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }

// acceptedHeavy streams prebuilt test inputs. Graph generation and parser
// preflight run in a separate build process, never in this small workload.
// An attempted transfer consumes its ordinal even if the client disconnects.
type acceptedHeavy struct {
	files [2]*os.File
	sizes [2]int64
	next  atomic.Uint32
}

func openAcceptedHeavy(paths [2]string) (*acceptedHeavy, error) {
	h := &acceptedHeavy{}
	for index, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			h.Close()
			return nil, err
		}
		h.files[index] = file
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<20 {
			h.Close()
			return nil, fmt.Errorf("invalid prebuilt profile input %d", index)
		}
		h.sizes[index] = info.Size()
	}
	return h, nil
}

func (h *acceptedHeavy) Close() {
	for _, file := range h.files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func (h *acceptedHeavy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if r.Method != http.MethodGet || err != nil || len(query) != 2 || len(query["debug"]) != 1 || query.Get("debug") != "0" || len(query["seconds"]) != 1 || query.Get("seconds") != "10" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.Context().Err() != nil {
		w.WriteHeader(http.StatusRequestTimeout)
		return
	}
	// Saturate at two so even repeated invalid retries cannot wrap the counter
	// and replay the fixed pair.
	var ordinal uint32
	for {
		ordinal = h.next.Load()
		if ordinal >= 2 {
			w.WriteHeader(http.StatusGone)
			return
		}
		if h.next.CompareAndSwap(ordinal, ordinal+1) {
			break
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(h.sizes[ordinal], 10))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.CopyN(w, io.NewSectionReader(h.files[ordinal], 0, h.sizes[ordinal]), h.sizes[ordinal])
}

// Test-owned application TLS material is mounted only in this synthetic Pod.
// A malformed explicit mode never falls back to a plaintext profile listener.
func profileWorkloadTLS(args []string) (*tls.Config, error) {
	if len(args) != 3 || args[0] != "--tls" {
		return nil, fmt.Errorf("invalid synthetic profile TLS arguments")
	}
	read := func(path string) ([]byte, error) {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 8<<10 {
			return nil, fmt.Errorf("invalid bounded profile TLS file")
		}
		data, err := io.ReadAll(io.LimitReader(file, (8<<10)+1))
		if err != nil || len(data) > 8<<10 {
			return nil, fmt.Errorf("invalid bounded profile TLS material")
		}
		return data, nil
	}
	cert, err := read(args[1])
	if err != nil {
		return nil, err
	}
	key, err := read(args[2])
	if err != nil {
		return nil, err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, nil
}
