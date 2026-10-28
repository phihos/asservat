//go:build ignore

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Real HTTP.Do waits for the next headers after one fully acknowledged batch.
// No collector, Docker, CPU throttling or installed-cause reconstruction.
func TestTrafficClientHeaderWaitDeadlineAndCancellation(t *testing.T) {
	for _, mode := range []string{"deadline", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			until, _ := ctx.Deadline()
			input, output := io.Pipe()
			joined := make(chan struct{})
			var inputCancels atomic.Int64
			go func() {
				defer close(joined)
				cancelTrafficOnInput(input, until, func() { inputCancels.Add(1); cancel() })
			}()
			defer func() { output.Close(); input.Close(); <-joined }()
			var calls atomic.Int64
			serve := trafficHandler()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					serve.ServeHTTP(w, r)
					return
				}
				if mode == "cancelled" {
					output.Close()
				}
				<-r.Context().Done() // Deliberately send no headers/body/ACK for this request.
			}))
			defer server.Close()
			got := runTrafficClient(ctx, server.URL)
			output.Close()
			<-joined
			wantCancel := int64(0)
			if mode == "cancelled" {
				wantCancel = 1
			}
			if inputCancels.Load() != wantCancel {
				t.Fatal("stdin replaced original deadline cause", inputCancels.Load(), ctx.Err())
			}
			want := "deadline"
			if mode == "cancelled" {
				want = "request"
			}
			if got.Failure != want || got.Batches != 1 || got.Records != 4096 || got.Bytes != 262144 || got.LastStatus != 0 || got.LastBodyBytes != 0 || got.LastAcknowledged || calls.Load() != 2 {
				t.Fatal("actual header-wait classification/receipt", mode, got, calls.Load())
			}
		})
	}
}

func TestTrafficClientConnectionResetIsRequestFailure(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Close()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	got := runTrafficClient(ctx, server.URL)
	if got.Failure != "request" || ctx.Err() != nil || got.Batches != 0 || got.Bytes != 0 || got.LastStatus != 0 || calls.Load() != 1 {
		t.Fatal("real request failure masked as deadline/retried", got, calls.Load(), ctx.Err())
	}
}

func TestTrafficClientBodyWaitKeepsDeadlineCause(t *testing.T) {
	var calls atomic.Int64
	serve := trafficHandler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			serve.ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(make([]byte, 64))
		http.NewResponseController(w).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	got := runTrafficClient(ctx, server.URL)
	if got.Failure != "deadline" || got.Batches != 1 || got.Records != 4096 || got.LastStatus != 200 || got.LastBodyBytes != 64 || got.LastAcknowledged || got.Bytes != 262208 || calls.Load() != 2 {
		t.Fatal("actual body-wait deadline lost", got, calls.Load())
	}
}

func TestTrafficDeadlineClassificationRefusesUnrelatedOrEarlyCancel(t *testing.T) {
	expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, item := range []struct {
		ctx  context.Context
		err  error
		want bool
	}{
		{expired, context.DeadlineExceeded, true},
		{expired, io.EOF, false}, {expired, context.Canceled, false}, {expired, nil, false},
		{cancelled, context.Canceled, false}, {cancelled, context.DeadlineExceeded, false},
		{t.Context(), context.DeadlineExceeded, false},
	} {
		if got := trafficDeadlineFailure(item.ctx, item.err); got != item.want {
			t.Fatal("unproven deadline accepted", got, item.want)
		}
	}
}
