package browser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/identity"
)

type transportSession struct {
	SessionService
	calls, refreshes, csrf int
	now                    time.Time
	revoked                bool
}

func (s *transportSession) Resolve(_ context.Context, _ string, refresh bool) (app.SessionView, error) {
	s.calls++
	if refresh {
		s.refreshes++
	}
	if s.revoked {
		return app.SessionView{}, identity.ErrDenied
	}
	if s.now.IsZero() {
		s.now = time.Now()
	}
	return app.SessionView{Identity: identity.Identity{Principal: identity.Principal{Issuer: "https://issuer.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}, Policy: identity.Revision{UID: "identity-policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: s.now, ValidUntil: s.now.Add(time.Minute)}, CSRF: strings.Repeat("C", 43), ExpiresAt: s.now.Add(time.Hour)}, nil
}
func (s *transportSession) CheckCSRF(_ context.Context, _ string, csrf string) error {
	s.csrf++
	if csrf != strings.Repeat("C", 43) {
		return identity.ErrDenied
	}
	return nil
}
func TestBrowserTransportFences(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"plain HTTP":             func(r *http.Request) { r.TLS = nil },
		"spoofed forwarded host": func(r *http.Request) { r.Host = "evil.invalid"; r.Header.Set("X-Forwarded-Host", "console.invalid") },
		"missing origin":         func(r *http.Request) { r.Header.Del("Origin") },
		"wrong origin":           func(r *http.Request) { r.Header.Set("Origin", "https://evil.invalid") },
		"duplicate origin":       func(r *http.Request) { r.Header.Add("Origin", "https://console.invalid") },
		"wrong CSRF":             func(r *http.Request) { r.Header.Set("X-CSRF-Token", strings.Repeat("D", 43)) },
		"duplicate CSRF":         func(r *http.Request) { r.Header.Add("X-CSRF-Token", strings.Repeat("C", 43)) },
		"duplicate cookie": func(r *http.Request) {
			r.URL.Scheme, r.URL.Host = "", ""
			r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
		},
		"mixed bearer":        func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic") },
		"cross-site metadata": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
	} {
		t.Run(name, func(t *testing.T) {
			s := &transportSession{}
			h := SessionHandler{Origin: "https://console.invalid", Sessions: s}
			r := httptest.NewRequest("POST", "https://console.invalid/auth/refresh", nil)
			r.URL.Scheme, r.URL.Host = "", ""
			r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
			r.Header.Set("Origin", h.Origin)
			r.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
			change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || s.calls != 0 {
				t.Fatalf("unsafe request reached identity: %d %d", w.Code, s.calls)
			}
			if w.Header().Get("Cache-Control") != "no-store, private" || w.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal("missing response protections")
			}
		})
	}
	s := &transportSession{}
	h := SessionHandler{Origin: "https://console.invalid", Sessions: s}
	r := httptest.NewRequest("GET", "https://console.invalid/api/v1/session", nil)
	r.URL.Scheme, r.URL.Host = "", ""
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || s.calls != 1 || s.refreshes != 0 || !strings.Contains(w.Body.String(), `"subject_id":"developer"`) || strings.Contains(w.Body.String(), "clientID") {
		t.Fatal("GET session changed credentials or wire contract")
	}
	w = httptest.NewRecorder()
	setSessionCookie(w, SessionCookie, "synthetic", time.Now().Add(time.Hour))
	c := w.Result().Cookies()[0]
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Domain != "" || c.Path != "/" {
		t.Fatal("session cookie flags")
	}
}

func TestBrowserOperationIdentityRechecksSessionWithoutAnotherRefresh(t *testing.T) {
	s := &transportSession{}
	h := SessionHandler{Origin: "https://console.invalid", Sessions: s}
	r := httptest.NewRequest("POST", "https://console.invalid/api/v1/operations/preview_capture", nil)
	r.URL.Scheme, r.URL.Host = "", ""
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
	r.Header.Set("Origin", h.Origin)
	r.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
	w := httptest.NewRecorder()
	current, initial, err := h.AuthenticateCurrent(w, r)
	if err != nil || !initial.Identity.Valid(time.Now()) || s.csrf != 1 || s.refreshes != 1 {
		t.Fatal("initial identity did not use authenticated mutation ingress", err)
	}
	if _, err = current.ResolveIdentity(context.Background()); err != nil || s.refreshes != 1 {
		t.Fatal("downstream authorization rotated the session", err)
	}
	s.revoked = true
	if _, err = current.ResolveIdentity(context.Background()); err == nil {
		t.Fatal("revoked browser identity survived into application authorization")
	}
	r.Header.Del("X-CSRF-Token")
	before := s.calls
	if _, _, err = h.AuthenticateCurrent(httptest.NewRecorder(), r); err == nil || s.calls != before {
		t.Fatal("missing CSRF reached session resolution")
	}
}
