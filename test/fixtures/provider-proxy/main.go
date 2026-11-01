//go:build ignore

// provider-proxy is an owned, synthetic integration fixture only. It has no
// product entry point or authority; it bridges TLS to private fixture backends.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 4 && os.Args[1] == "traffic-client" {
		deadline, err := time.Parse(time.RFC3339Nano, os.Args[3])
		ip := net.ParseIP(os.Args[2])
		if err != nil || ip == nil || !ip.IsPrivate() || ip.IsLoopback() || !deadline.After(time.Now()) || time.Until(deadline) > 8500*time.Millisecond {
			fmt.Fprintln(os.Stderr, "traffic client input refused")
			os.Exit(1)
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		go cancelTrafficOnInput(os.Stdin, deadline, cancel)
		receipt := runTrafficClient(ctx, "http://"+net.JoinHostPort(ip.String(), "8080"))
		_ = json.NewEncoder(os.Stdout).Encode(receipt)
		if receipt.Failure != "" {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "signals" {
		if err := signals(); err != nil {
			fmt.Fprintln(os.Stderr, "synthetic signal workload failed")
			os.Exit(1)
		}
		return
	}
	if err := serve(); err != nil {
		fmt.Fprintln(os.Stderr, "synthetic TLS provider fixture failed")
		os.Exit(1)
	}
}
func serve() error {
	if len(os.Args) != 4 {
		return fmt.Errorf("arguments")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	var ip net.IP
	for _, a := range addresses {
		v, _, e := net.ParseCIDR(a.String())
		if e == nil && v.To4() != nil && v.IsPrivate() && !v.IsLoopback() {
			if ip != nil {
				return fmt.Errorf("multiple networks")
			}
			ip = v
		}
	}
	if ip == nil {
		return fmt.Errorf("private network missing")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return err
	}
	cert := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{ip}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	failures := make(chan error, 3)
	counters := &providerCounters{}
	for i, port := range []string{"8443", "8444"} {
		upstream, e := url.Parse(os.Args[i+1])
		if e != nil || upstream.Scheme != "http" || upstream.Host == "" {
			return fmt.Errorf("backend")
		}
		proxy := httputil.NewSingleHostReverseProxy(upstream)
		transport := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 5 * time.Second}
		defer transport.CloseIdleConnections()
		proxy.Transport = providerCounterTransport{next: transport, counters: counters, provider: i}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
			http.Error(w, "fixture backend unavailable", http.StatusBadGateway)
		}
		ln, e := tls.Listen("tcp", net.JoinHostPort(ip.String(), port), config)
		if e != nil {
			return e
		}
		server := &http.Server{Handler: counters.handler(proxy), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 32768}
		defer server.Close()
		go func() { failures <- server.Serve(ln) }()
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "8445"))
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				failures <- e
				return
			}
			go postgres(conn, os.Args[3], config)
		}
	}()
	// Public certificate and endpoints only; never log proxy bodies or credentials.
	if err = json.NewEncoder(os.Stdout).Encode(struct {
		S3, KMS, Postgres string
		Root              []byte
	}{"https://" + ip.String() + ":8443", "https://" + ip.String() + ":8444", ip.String() + ":8445", der}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-failures:
		return err
	}
}
func postgres(raw net.Conn, backend string, config *tls.Config) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	var request [8]byte
	if _, err := io.ReadFull(raw, request[:]); err != nil || request != [8]byte{0, 0, 0, 8, 4, 210, 22, 47} {
		return
	}
	if _, err := raw.Write([]byte("S")); err != nil {
		return
	}
	conn := tls.Server(raw, config)
	if conn.Handshake() != nil {
		return
	}
	upstream, err := net.DialTimeout("tcp", backend, time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	_ = raw.SetDeadline(time.Time{})
	joined := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close(); close(joined) }()
	_, _ = io.Copy(conn, upstream)
	_ = conn.Close()
	<-joined
}

// signals is the ADR-241 installed log/resource focus workload: on GET
// /log?line=<text> it writes one synthetic line to stdout; on GET
// /burn?seconds=<n> it keeps one CPU busy for n seconds (at most 300). It
// reads no input besides these parameters and exits on SIGTERM.
func signals() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	mux := http.NewServeMux()
	mux.Handle("/traffic", trafficHandler())
	mux.HandleFunc("/log", func(w http.ResponseWriter, r *http.Request) {
		line := r.URL.Query().Get("line")
		if line == "" || len(line) > 4096 {
			http.Error(w, "line", http.StatusBadRequest)
			return
		}
		fmt.Fprintln(os.Stdout, line)
	})
	mux.HandleFunc("/burn", func(w http.ResponseWriter, r *http.Request) {
		var seconds int
		if _, err := fmt.Sscan(r.URL.Query().Get("seconds"), &seconds); err != nil || seconds < 1 || seconds > 300 {
			http.Error(w, "seconds", http.StatusBadRequest)
			return
		}
		go func() {
			for end := time.Now().Add(time.Duration(seconds) * time.Second); time.Now().Before(end) && ctx.Err() == nil; {
			}
		}()
	})
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = server.Close() }()
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

const (
	trafficMaxRecords    = 65536
	trafficRecordBytes   = 64
	trafficMaxPayload    = trafficMaxRecords * trafficRecordBytes
	trafficMaxDuration   = 8 * time.Second
	trafficBatchInterval = 250 * time.Millisecond
)

// Handler streams finite small flushed writes through the selected workload's
// existing HTTP port. TCP segmentation/ACKs are measured by the real recorder,
// not inferred from these application writes. Capture limits remain independent.
func trafficHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if r.Method != http.MethodGet || len(query) > 1 || len(query["records"]) > 1 {
			http.Error(w, "traffic request", http.StatusBadRequest)
			return
		}
		records := trafficMaxRecords
		if len(query) == 1 {
			n, err := strconv.Atoi(query.Get("records"))
			if err != nil || n < 1 || n > trafficMaxRecords {
				http.Error(w, "traffic records", http.StatusBadRequest)
				return
			}
			records = n
		}
		ctx, cancel := context.WithTimeout(r.Context(), trafficMaxDuration)
		defer cancel()
		until, _ := ctx.Deadline()
		control := http.NewResponseController(w)
		if ctx.Err() != nil || control.SetWriteDeadline(until) != nil {
			http.Error(w, "traffic deadline unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Fixture-Traffic-Max-Bytes", strconv.Itoa(records*trafficRecordBytes))
		w.Header().Set("Trailer", "X-Fixture-Traffic-Writes, X-Fixture-Traffic-Bytes, X-Fixture-Traffic-Complete")
		var written, bytes int
		var complete bool
		defer func() {
			w.Header().Set("X-Fixture-Traffic-Writes", strconv.Itoa(written))
			w.Header().Set("X-Fixture-Traffic-Bytes", strconv.Itoa(bytes))
			w.Header().Set("X-Fixture-Traffic-Complete", strconv.FormatBool(complete))
		}()
		var record [trafficRecordBytes]byte
		for i := range record {
			record[i] = byte(i + 1)
		}
		for written < records && ctx.Err() == nil {
			n, err := w.Write(record[:])
			bytes += n
			if err != nil || n != len(record) {
				return
			}
			written++
			if control.Flush() != nil {
				return
			}
		}
		complete = written == records && ctx.Err() == nil
	})
}

// Provider measurement is fixture-only. It records fixed numeric categories,
// never request identifiers or values. The underlying objects are not wrapped:
// request/response bodies and their streaming/upgrade interfaces stay intact.
const providerCounterPath = "/__asservat_fixture/counters"

var providerCounterNames = [...]string{
	"s3_get", "s3_head", "s3_put", "s3_post", "s3_delete", "s3_other",
	"kms_encrypt", "kms_decrypt", "kms_sign", "kms_verify", "kms_login",
	"kms_lookup", "kms_renew", "kms_revoke", "kms_other",
}

type providerCounterValues struct {
	Dispatches        int64 `json:"dispatches"`
	Active            int64 `json:"active_roundtrips"`
	TransportErrors   int64 `json:"transport_errors"`
	Status2xx         int64 `json:"status_2xx"`
	Status3xx         int64 `json:"status_3xx"`
	Status4xx         int64 `json:"status_4xx"`
	Status5xx         int64 `json:"status_5xx"`
	StatusOther       int64 `json:"status_other"`
	HeaderNanoseconds int64 `json:"roundtrip_to_headers_nanoseconds"`
}

type providerCounters struct {
	mu     sync.Mutex
	values [len(providerCounterNames)]providerCounterValues
}

type providerCounterTransport struct {
	next     http.RoundTripper
	counters *providerCounters
	provider int // existing serve loop: 0=S3, 1=KMS; SQL is unchanged
}

func providerCounterCategory(provider int, request *http.Request) int {
	if provider == 0 {
		switch request.Method {
		case http.MethodGet:
			return 0
		case http.MethodHead:
			return 1
		case http.MethodPut:
			return 2
		case http.MethodPost:
			return 3
		case http.MethodDelete:
			return 4
		default:
			return 5
		}
	}
	if request.URL == nil {
		return 14
	}
	// Inspect only operation positions. No path or query value is retained.
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	last := parts[len(parts)-1]
	auth := len(parts) >= 4 && parts[0] == "v1" && parts[1] == "auth"
	if auth && parts[2] == "token" && request.Method == http.MethodGet && last == "lookup-self" {
		return 11
	}
	if request.Method != http.MethodPost {
		return 14
	}
	if auth {
		if last == "login" {
			return 10
		}
		if parts[2] == "token" {
			switch last {
			case "renew-self":
				return 12
			case "revoke-self":
				return 13
			}
		}
	}
	if len(parts) >= 4 && parts[0] == "v1" {
		switch parts[len(parts)-2] {
		case "encrypt":
			return 6
		case "decrypt":
			return 7
		case "sign":
			return 8
		case "verify":
			return 9
		}
	}
	return 14
}

func (t providerCounterTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	index := providerCounterCategory(t.provider, request)
	t.counters.mu.Lock()
	t.counters.values[index].Dispatches++
	t.counters.values[index].Active++
	t.counters.mu.Unlock()
	started := time.Now()
	response, err := t.next.RoundTrip(request)
	elapsed := time.Since(started).Nanoseconds()
	t.counters.mu.Lock()
	defer t.counters.mu.Unlock()
	v := &t.counters.values[index]
	v.Active--
	v.HeaderNanoseconds += elapsed
	if err != nil || response == nil {
		v.TransportErrors++
	} else {
		switch response.StatusCode / 100 {
		case 2:
			v.Status2xx++
		case 3:
			v.Status3xx++
		case 4:
			v.Status4xx++
		case 5:
			v.Status5xx++
		default:
			v.StatusOther++
		}
	}
	return response, err
}

func (c *providerCounters) snapshot() map[string]providerCounterValues {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make(map[string]providerCounterValues, len(providerCounterNames))
	for i, name := range providerCounterNames {
		result[name] = c.values[i]
	}
	return result
}

func (c *providerCounters) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != providerCounterPath {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(c.snapshot())
	})
}

// Fixed owned-node traffic client. It uses the selected Pod IP directly;
// no proxy environment, redirect, replacement target or retry is available.
type trafficClientReceipt struct {
	Batches, Records, Bytes  int64
	Elapsed                  time.Duration
	WaitElapsed, WorkElapsed time.Duration
	Failure                  string
	LastStatus               int
	LastBodyBytes            int64
	LastAcknowledged         bool
}

func runTrafficClient(ctx context.Context, endpoint string) (out trafficClientReceipt) {
	started := time.Now()
	var workStarted time.Time
	finishWork := func() {
		if !workStarted.IsZero() {
			out.WorkElapsed += time.Since(workStarted)
			workStarted = time.Time{}
		}
	}
	defer func() { finishWork(); out.Elapsed = time.Since(started) }()
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for i := 0; i < 16; i++ {
		waitStarted := time.Now()
		wait := time.NewTimer(max(0, time.Until(started.Add(time.Duration(i)*trafficBatchInterval))))
		select {
		case <-ctx.Done():
			wait.Stop()
			out.WaitElapsed += time.Since(waitStarted)
			out.Failure = "request"
			if trafficDeadlineFailure(ctx, ctx.Err()) {
				out.Failure = "deadline"
			}
			return out
		case <-wait.C:
		}
		out.WaitElapsed += time.Since(waitStarted)
		workStarted = time.Now()
		out.LastStatus = 0
		out.LastBodyBytes = 0
		out.LastAcknowledged = false
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/traffic?records=4096", nil)
		if err != nil {
			out.Failure = "request"
			return out
		}
		response, err := client.Do(request)
		if err != nil {
			out.Failure = "request"
			if trafficDeadlineFailure(ctx, err) {
				out.Failure = "deadline"
			}
			return out
		}
		out.LastStatus = response.StatusCode
		n, err := io.Copy(io.Discard, io.LimitReader(response.Body, 262145))
		response.Body.Close()
		out.Bytes += n
		out.LastBodyBytes = n
		if err != nil || response.StatusCode != http.StatusOK || n != 262144 || response.Header.Get("X-Fixture-Traffic-Max-Bytes") != "262144" || response.Trailer.Get("X-Fixture-Traffic-Writes") != "4096" || response.Trailer.Get("X-Fixture-Traffic-Bytes") != "262144" || response.Trailer.Get("X-Fixture-Traffic-Complete") != "true" {
			out.Failure = "acknowledgement"
			if trafficDeadlineFailure(ctx, err) {
				out.Failure = "deadline"
			}
			return out
		}
		out.LastAcknowledged = true
		out.Batches++
		out.Records += 4096
		finishWork()
	}
	if ctx.Err() != nil {
		out.Failure = "request"
		if trafficDeadlineFailure(ctx, ctx.Err()) {
			out.Failure = "deadline"
		}
	}
	return out
}

// EOF owns early cancellation only. Once the original absolute cutoff has
// passed, its existing WithDeadline timer owns the cause; EOF must not replace
// an already-due deadline with context.Canceled. No timer or interval is added.
func cancelTrafficOnInput(input io.Reader, until time.Time, cancel context.CancelFunc) {
	var one [1]byte
	_, _ = input.Read(one[:])
	if time.Now().Before(until) {
		cancel()
	}
}

// Both the actual HTTP/read error and the original context must report the
// supported deadline cause. An unrelated failure near the cutoff stays failed.
func trafficDeadlineFailure(ctx context.Context, err error) bool {
	return errors.Is(err, context.DeadlineExceeded) && errors.Is(ctx.Err(), context.DeadlineExceeded)
}
