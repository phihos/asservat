// Synthetic workload for native profile qualification. Never shipped in the product image.
package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"runtime"
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
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("synthetic profile workload\n")) })
	redirect := http.NewServeMux()
	redirect.HandleFunc("/debug/pprof/profile", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:6060/debug/pprof/profile?seconds=1", http.StatusFound)
	})
	go func() {
		log.Fatal((&http.Server{Addr: "127.0.0.1:6070", Handler: redirect, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
	}()
	go func() {
		log.Fatal((&http.Server{Addr: "127.0.0.1:6060", ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
	}()
	log.Fatal((&http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
}
