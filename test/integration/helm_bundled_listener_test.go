package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"asservat.local/asservat/internal/transport/browser"
)

func TestHelmBundledPublicListenerAcceptsActualUnauthenticatedSession(t *testing.T) {
	var origin string
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		// Exercise the production no-cookie branch, rather than fabricating a
		// status which could disagree with the real browser session contract.
		browser.SessionHandler{Origin: origin, Sessions: &consoleSyntheticSessions{}}.ServeHTTP(w, r)
	}))
	defer server.Close()
	origin = server.URL
	ctx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if err := waitHelmBundledPublicListener(ctx, server.Client(), origin); err != nil || requests != 1 {
		t.Fatal("actual no-cookie session contract rejected as listener failure", err, requests)
	}
}

func TestHelmBundledPublicListenerRetriesOnlyUnavailableAndPreservesCancellation(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(status) }))
			defer server.Close()
			if err := waitHelmBundledPublicListener(t.Context(), server.Client(), server.URL); err == nil || requests != 1 {
				t.Fatal("unrelated failure accepted or retried", err, requests)
			}
		})
	}
	requests := 0
	var origin string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		browser.SessionHandler{Origin: origin, Sessions: &consoleSyntheticSessions{}}.ServeHTTP(w, r)
	}))
	defer server.Close()
	origin = server.URL
	if err := waitHelmBundledPublicListener(t.Context(), server.Client(), origin); err != nil || requests != 2 {
		t.Fatal("unavailable-to-actual-listener transition failed", err, requests)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := waitHelmBundledPublicListener(ctx, server.Client(), origin); err == nil {
		t.Fatal("cancelled original parent accepted")
	}
}
