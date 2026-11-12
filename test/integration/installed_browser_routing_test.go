package integration

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The selected native chart exposes console and Keycloak on the SAME node IP
// with different ports. A hostname-only fixture remap sends the IdP request to
// the console and cannot qualify the actual imported identity provider.
func TestInstalledConsoleSessionRoutesSharedHostByExactAuthority(t *testing.T) {
	const origin = "https://127.0.0.1:31450"
	var identityBase string
	var providerRequests atomic.Int32
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerRequests.Add(1)
		switch r.Method + " " + r.URL.Path {
		case "GET /realms/asservat/protocol/openid-connect/auth":
			fmt.Fprint(w, `<form id="kc-form-login" action="`+identityBase+`/realms/asservat/login-actions/authenticate?session=original"></form>`)
		case "POST /realms/asservat/login-actions/authenticate":
			if r.ParseForm() != nil || r.Form.Get("username") != "developer" || r.Form.Get("password") != "fixture-human-password" {
				t.Error("actual identity form was changed")
			}
			w.Header().Set("Location", origin+"/auth/callback?code=original")
			w.WriteHeader(http.StatusFound)
		default:
			t.Error("unexpected IdP request")
			w.WriteHeader(400)
		}
	}))
	defer provider.Close()
	identityBase = provider.URL
	var publicRequests atomic.Int32
	public := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicRequests.Add(1)
		switch r.URL.Path {
		case "/auth/login":
			w.Header().Set("Location", identityBase+"/realms/asservat/protocol/openid-connect/auth")
			w.WriteHeader(http.StatusSeeOther)
		case "/auth/callback":
			if r.URL.Query().Get("code") != "original" {
				t.Error("callback lost original code")
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "synthetic-cookie", Path: "/", Secure: true, HttpOnly: true})
			w.Header().Set("Location", origin+"/investigations")
			w.WriteHeader(http.StatusSeeOther)
		case "/api/v1/session":
			if _, err := r.Cookie("session"); err != nil {
				t.Error("cookie session was not retained")
			}
			fmt.Fprint(w, `{"csrf_token":"`+strings.Repeat("a", 43)+`"}`)
		default:
			t.Errorf("IdP request was misrouted to the public origin: %s", r.URL.Path)
			w.WriteHeader(400)
		}
	}))
	defer public.Close()
	identity := &installedIdentity{Issuer: identityBase + "/realms/asservat", RootPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw})), kc: &kcFixture{UserPassword: "fixture-human-password"}}
	root, err := x509.ParseCertificate(public.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	session := identity.consoleSession(t, ctx, root, public.Listener.Addr().String(), origin)
	if session.csrf != strings.Repeat("a", 43) || providerRequests.Load() != 2 || publicRequests.Load() != 3 {
		t.Fatal("actual TLS redirect/session path changed", providerRequests.Load(), publicRequests.Load())
	}
}
