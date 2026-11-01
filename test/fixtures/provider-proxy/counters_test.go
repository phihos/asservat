//go:build ignore

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type providerRoundTripFunc func(*http.Request) (*http.Response, error)

func (f providerRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type providerIdentityBody struct {
	bytes.Buffer
	closes int
}

func (b *providerIdentityBody) Close() error { b.closes++; return nil }

func TestProviderCountersPreserveObjectsAndErrors(t *testing.T) {
	counters := &providerCounters{}
	requestBody, responseBody := &providerIdentityBody{}, &providerIdentityBody{}
	requestBody.WriteString("synthetic-sensitive-request")
	responseBody.WriteString("synthetic-sensitive-response")
	request, _ := http.NewRequest(http.MethodPut, "http://fixture.invalid/synthetic-sensitive-object?token=synthetic-sensitive-query", requestBody)
	request.Header.Set("Authorization", "synthetic-sensitive-header")
	response := &http.Response{StatusCode: 503, Body: responseBody}
	wantErr := errors.New("synthetic backend refusal")
	var calls int
	transport := providerCounterTransport{counters: counters, provider: 0, next: providerRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r != request || r.Body != requestBody {
			t.Error("counter changed request or body identity")
		}
		return response, wantErr
	})}
	got, err := transport.RoundTrip(request)
	if got != response || got.Body != responseBody || err != wantErr || calls != 1 {
		t.Fatal("counter changed response/error or retried", got == response, err, calls)
	}
	// Exact identity also retains Reader/Writer/WriterTo/ReaderFrom interfaces.
	if requestBody.String() != "synthetic-sensitive-request" || responseBody.String() != "synthetic-sensitive-response" || requestBody.closes != 0 || responseBody.closes != 0 {
		t.Fatal("counter consumed or closed a body")
	}
	if request.Header.Get("Authorization") != "synthetic-sensitive-header" || request.URL.RawQuery != "token=synthetic-sensitive-query" {
		t.Fatal("counter modified request metadata")
	}
	snapshot := counters.snapshot()
	if len(snapshot) != len(providerCounterNames) || snapshot["s3_put"].Dispatches != 1 || snapshot["s3_put"].TransportErrors != 1 || snapshot["s3_put"].Active != 0 {
		t.Fatal("incorrect fixed totals", snapshot["s3_put"])
	}
	encoded, _ := json.Marshal(snapshot)
	if strings.Contains(string(encoded), "synthetic-sensitive") {
		t.Fatal("request/body/header/query identifier entered counter snapshot")
	}
}

func TestProviderCounterFixedCategories(t *testing.T) {
	cases := []struct {
		provider               int
		method, path, category string
	}{
		{0, "GET", "/bucket/object", "s3_get"}, {0, "HEAD", "/bucket/object", "s3_head"},
		{0, "PUT", "/bucket/object", "s3_put"}, {0, "POST", "/bucket?uploads", "s3_post"},
		{0, "DELETE", "/bucket/object", "s3_delete"}, {0, "PATCH", "/unknown", "s3_other"},
		{1, "POST", "/v1/mount/encrypt/key", "kms_encrypt"},
		{1, "POST", "/v1/mount/encrypt/login", "kms_encrypt"},
		{1, "GET", "/v1/kv/lookup-self", "kms_other"}, {1, "POST", "/v1/mount/decrypt/key", "kms_decrypt"},
		{1, "POST", "/v1/mount/sign/key", "kms_sign"}, {1, "POST", "/v1/mount/verify/key", "kms_verify"},
		{1, "POST", "/v1/auth/mount/login", "kms_login"}, {1, "GET", "/v1/auth/token/lookup-self", "kms_lookup"},
		{1, "POST", "/v1/auth/token/renew-self", "kms_renew"}, {1, "POST", "/v1/auth/token/revoke-self", "kms_revoke"},
		{1, "GET", "/v1/unknown/variable-key", "kms_other"},
	}
	for _, c := range cases {
		r, _ := http.NewRequest(c.method, "http://fixture.invalid"+c.path, nil)
		if got := providerCounterNames[providerCounterCategory(c.provider, r)]; got != c.category {
			t.Fatal("fixed operation classification", got, c.category)
		}
	}
}

func TestProviderCounterConcurrentSnapshotsExcludeTheirOwnReads(t *testing.T) {
	counters := &providerCounters{}
	transport := providerCounterTransport{counters: counters, provider: 0, next: providerRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
	})}
	var forwarded atomic.Int64
	handler := counters.handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded.Add(1) }))
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 100 {
				r, _ := http.NewRequest(http.MethodGet, "http://fixture.invalid/variable-object?prefix=sensitive", nil)
				_, _ = transport.RoundTrip(r)
			}
		})
	}
	for range 100 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, providerCounterPath, nil))
		var snapshot map[string]providerCounterValues
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &snapshot) != nil || len(snapshot) != len(providerCounterNames) {
			t.Fatal("invalid concurrent snapshot")
		}
	}
	workers.Wait()
	if forwarded.Load() != 0 || counters.snapshot()["s3_get"].Dispatches != 400 || counters.snapshot()["s3_get"].Active != 0 {
		t.Fatal("snapshot forwarded/counted itself or lost concurrent dispatches")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, providerCounterPath, nil))
	if w.Code != 405 || forwarded.Load() != 0 {
		t.Fatal("snapshot allowed a mutation/forward")
	}
}

func TestProviderCountersLeaveRealTLSStreamingUnbuffered(t *testing.T) {
	var backendCalls atomic.Int64
	release := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls.Add(1)
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "second")
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	counters := &providerCounters{}
	proxy.Transport = providerCounterTransport{next: transport, counters: counters, provider: 0}
	front := httptest.NewUnstartedServer(counters.handler(proxy))
	front.EnableHTTP2 = true
	front.StartTLS()
	defer front.Close()
	defer finish()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, front.URL+"/bucket/object", nil)
	response, err := front.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	first := make([]byte, 5)
	if _, err := io.ReadFull(response.Body, first); err != nil || string(first) != "first" || response.ProtoMajor != 2 {
		t.Fatal("counter blocked or altered first streaming bytes", err)
	}
	snapshot, err := front.Client().Get(front.URL + providerCounterPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, snapshot.Body)
	snapshot.Body.Close()
	if backendCalls.Load() != 1 || counters.snapshot()["s3_get"].Dispatches != 1 {
		t.Fatal("snapshot reached backend or entered provider dispatch count")
	}
	finish()
	second, err := io.ReadAll(response.Body)
	if err != nil || string(second) != "second" {
		t.Fatal("streaming response changed", err)
	}
}

func TestProviderCounterActiveAndStatusSnapshot(t *testing.T) {
	counters := &providerCounters{}
	entered, release := make(chan struct{}), make(chan struct{})
	transport := providerCounterTransport{counters: counters, provider: 1, next: providerRoundTripFunc(func(*http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return &http.Response{StatusCode: 403, Body: http.NoBody}, nil
	})}
	request, _ := http.NewRequest(http.MethodPost, "http://fixture.invalid/v1/mount/decrypt/key", nil)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = transport.RoundTrip(request) }()
	<-entered
	active := counters.snapshot()["kms_decrypt"]
	close(release)
	<-done
	finished := counters.snapshot()["kms_decrypt"]
	if active.Dispatches != 1 || active.Active != 1 || active.HeaderNanoseconds != 0 {
		t.Fatal("snapshot lost in-flight header observation", active)
	}
	if finished.Dispatches != 1 || finished.Active != 0 || finished.Status4xx != 1 || finished.TransportErrors != 0 || finished.HeaderNanoseconds <= 0 {
		t.Fatal("snapshot changed provider status or lost completion", finished)
	}
}
