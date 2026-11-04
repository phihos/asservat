//go:build ignore

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type disconnectedProfileWriter struct{ header http.Header }

func (w disconnectedProfileWriter) Header() http.Header { return w.header }
func (disconnectedProfileWriter) WriteHeader(int)       {}
func (disconnectedProfileWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic disconnected client")
}

func TestAcceptedHeavyCancellationAndFailedTransferDoNotReplay(t *testing.T) {
	dir := t.TempDir()
	var paths [2]string
	for index, side := range []string{"baseline", "incident"} {
		paths[index] = filepath.Join(dir, side)
		if err := os.WriteFile(paths[index], []byte(side), 0600); err != nil {
			t.Fatal(err)
		}
	}
	handler, err := openAcceptedHeavy(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handler.Close)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reply := httptest.NewRecorder()
	handler.ServeHTTP(reply, httptest.NewRequest("GET", "/debug/pprof/profile?debug=0&seconds=10", nil).WithContext(ctx))
	if reply.Code != http.StatusRequestTimeout || handler.next.Load() != 0 {
		t.Fatal("canceled request consumed input", reply.Code, handler.next.Load())
	}
	handler.ServeHTTP(disconnectedProfileWriter{header: make(http.Header)}, httptest.NewRequest("GET", "/debug/pprof/profile?debug=0&seconds=10", nil))
	reply = httptest.NewRecorder()
	handler.ServeHTTP(reply, httptest.NewRequest("GET", "/debug/pprof/profile?debug=0&seconds=10", nil))
	if reply.Code != 200 || reply.Body.String() != "incident" {
		t.Fatalf("failed baseline transfer replayed: %d %q", reply.Code, reply.Body)
	}
}

func TestAcceptedHeavyServesExactPairWithoutReplay(t *testing.T) {
	dir := t.TempDir()
	var paths [2]string
	for index, side := range []string{"baseline", "incident"} {
		paths[index] = filepath.Join(dir, side)
		if err := os.WriteFile(paths[index], []byte(side), 0600); err != nil {
			t.Fatal(err)
		}
	}
	handler, err := openAcceptedHeavy(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handler.Close)
	for _, bad := range []struct{ method, query string }{{"POST", "?debug=0&seconds=10"}, {"GET", "?debug=0&seconds=1"}, {"GET", "?debug=0&seconds=10&gc=1"}, {"GET", "?debug=0&seconds=10&seconds=10"}, {"GET", "?debug=0&seconds=10&bad=%zz"}} {
		reply := httptest.NewRecorder()
		handler.ServeHTTP(reply, httptest.NewRequest(bad.method, "/debug/pprof/profile"+bad.query, nil))
		if reply.Code < 400 {
			t.Fatalf("accepted invalid request %v", bad)
		}
	}
	for _, expected := range []string{"baseline", "incident", ""} {
		reply := httptest.NewRecorder()
		handler.ServeHTTP(reply, httptest.NewRequest("GET", "/debug/pprof/profile?debug=0&seconds=10", nil))
		if expected == "" {
			if reply.Code != http.StatusGone || strings.Contains(reply.Body.String(), "baseline") || strings.Contains(reply.Body.String(), "incident") {
				t.Fatalf("replayed exhausted pair: %d %q", reply.Code, reply.Body)
			}
		} else if reply.Code != 200 || reply.Body.String() != expected || reply.Header().Get("Content-Length") != fmt.Sprint(len(expected)) {
			t.Fatalf("wrong immutable input: %d %q", reply.Code, reply.Body)
		}
	}
}

func TestAcceptedHeavyConcurrentRequestsAreFinite(t *testing.T) {
	dir := t.TempDir()
	var paths [2]string
	for index := range paths {
		paths[index] = filepath.Join(dir, fmt.Sprint(index))
		if err := os.WriteFile(paths[index], []byte(fmt.Sprint(index)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	handler, err := openAcceptedHeavy(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handler.Close)
	results := make(chan string, 8)
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			reply := httptest.NewRecorder()
			handler.ServeHTTP(reply, httptest.NewRequest("GET", "/debug/pprof/profile?debug=0&seconds=10", nil))
			if reply.Code == 200 {
				results <- reply.Body.String()
			}
		})
	}
	group.Wait()
	close(results)
	counts := map[string]int{}
	for value := range results {
		counts[value]++
	}
	if counts["0"] != 1 || counts["1"] != 1 || len(counts) != 2 {
		t.Fatal(counts)
	}
}

func TestAcceptedHeavyRejectsMissingEmptyOrOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid")
	if err := os.WriteFile(valid, []byte("profile"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int64{0, (16 << 20) + 1} {
		bad := filepath.Join(dir, fmt.Sprint(size))
		file, err := os.Create(bad)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(size); err != nil {
			t.Fatal(err)
		}
		file.Close()
		if handler, err := openAcceptedHeavy([2]string{valid, bad}); err == nil {
			handler.Close()
			t.Fatal("accepted invalid file size", size)
		}
	}
	if handler, err := openAcceptedHeavy([2]string{valid, filepath.Join(dir, "absent")}); err == nil {
		handler.Close()
		t.Fatal("accepted missing second input")
	}
}

func TestProfileTLSFixtureRequiresExactFilesAndVerifiedPeer(t *testing.T) {
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	defer seed.Close()
	directory := t.TempDir()
	certificate := filepath.Join(directory, "app.crt")
	keyPath := filepath.Join(directory, "app.key")
	pair := seed.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	clear(key)
	config, err := profileWorkloadTLS([]string{"--tls", certificate, keyPath})
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	app := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.TLS == nil || r.ProtoMajor != 1 {
			t.Error("fixture served profile without HTTP1.1 TLS")
		}
		_, _ = io.WriteString(w, "native")
	}))
	app.TLS = config
	app.StartTLS()
	defer app.Close()
	roots := x509.NewCertPool()
	roots.AddCert(seed.Certificate())
	for _, name := range []string{"127.0.0.1", "wrong.fixture.invalid"} {
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: time.Second}
		response, err := client.Get(app.URL + "/debug/pprof/profile?debug=0&seconds=10")
		if name == "127.0.0.1" {
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if string(raw) != "native" {
				t.Fatal("fixture TLS payload")
			}
		} else if err == nil {
			response.Body.Close()
			t.Fatal("wrong TLS identity reached HTTP")
		}
	}
	if requests.Load() != 1 {
		t.Fatal("failed peer handshake reached application handler", requests.Load())
	}
	for _, args := range [][]string{nil, {"--tls"}, {"--accepted-heavy", certificate, keyPath}, {"--tls", certificate, keyPath, "extra"}, {"--tls", certificate, "missing"}} {
		if _, err := profileWorkloadTLS(args); err == nil {
			t.Fatal("explicit invalid TLS mode fell back", args)
		}
	}
	if err := os.WriteFile(certificate, []byte(strings.Repeat("x", 8193)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := profileWorkloadTLS([]string{"--tls", certificate, keyPath}); err == nil {
		t.Fatal("unbounded TLS file accepted")
	}
}
