package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/identity"
)

// The real handler can finish its Content-Length body before it acknowledges
// the SQL outcome. Join its return before interpreting any durable result.
// This test-only barrier observes completion; it changes no transport authority.
func nativeContentJoinedHandler(next http.Handler) (http.Handler, <-chan struct{}) {
	done := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { done <- struct{}{} }()
		next.ServeHTTP(w, r)
	}), done
}
func waitContextNativeHTTP(t *testing.T, ctx context.Context, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("native HTTP handler did not join under original caller deadline", ctx.Err())
	}
}

func TestNativeContentFixtureUsesItsExactHTTPCookie(t *testing.T) {
	now := time.Now()
	initial := identity.Identity{Principal: identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic-native-reader", ClientID: "console", Kind: identity.Human}, Policy: identity.Revision{UID: "synthetic-policy", Generation: 1, Digest: [32]byte{1}}, Scopes: []string{"evidence:read", "evidence:download"}, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}
	store := workerBrowserSession{initial, now.Add(time.Minute), 5 * time.Second}
	sessions := nativeContentSessions{store}
	current, view, err := identities.NewBrowserRequest(t.Context(), sessions, strings.Repeat("s", 43), false, time.Now)
	if err != nil {
		t.Fatal("HTTP fixture cookie rejected before real C02 reader", err)
	}
	resolved, err := current.ResolveIdentity(t.Context())
	if err != nil || resolved.Principal != initial.Principal || !view.ExpiresAt.Equal(store.expires) || resolved.ValidUntil.After(view.Identity.ValidUntil) {
		t.Fatal("original synthetic session/deadline changed", err)
	}
	for _, cookie := range []string{"", "synthetic-worker-session", strings.Repeat("x", 43), strings.Repeat("s", 42)} {
		if _, err := sessions.Resolve(t.Context(), cookie, false); err == nil {
			t.Fatal("unrelated HTTP cookie admitted")
		}
	}
	if _, err := sessions.Resolve(t.Context(), strings.Repeat("s", 43), true); err == nil {
		t.Fatal("GET fixture refreshed")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := sessions.Resolve(canceled, strings.Repeat("s", 43), false); err == nil {
		t.Fatal("canceled fixture identity admitted")
	}
	if _, err := store.Resolve(t.Context(), "synthetic-worker-session", false); err != nil {
		t.Fatal("existing non-HTTP fixture behavior changed", err)
	}
	if _, err := store.Resolve(t.Context(), strings.Repeat("s", 43), false); err == nil {
		t.Fatal("ordinary fixture accepted HTTP cookie")
	}
}

func TestNativeContentFixtureJoinsHandlerAfterBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	release := make(chan struct{})
	handler, joined := nativeContentJoinedHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1")
		_, _ = w.Write([]byte("x"))
		_ = http.NewResponseController(w).Flush()
		select {
		case <-release:
		case <-ctx.Done():
		}
	}))
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "x" {
		t.Fatal("body", err)
	}
	select {
	case <-joined:
		t.Fatal("body completion mistaken for joined SQL handler")
	default:
	}
	close(release)
	waitContextNativeHTTP(t, ctx, joined)
}
