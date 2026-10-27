package browser

import (
	app "asservat.local/asservat/internal/application/identity"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type stepupSessions struct {
	SessionService
	calls int
	path  string
}

func (s *stepupSessions) BeginStepUp(_ context.Context, path string) (app.LoginRedirect, error) {
	s.calls++
	s.path = path
	return app.LoginRedirect{URL: "https://issuer.invalid/auth", Browser: strings.Repeat("A", 43), ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func TestStepUpIngressAllowsOnlyLocalReturnParameter(t *testing.T) {
	for _, query := range []string{"return_to=%2Fapprovals%2Frequest", "acr_values=evil", "max_age=3600", "return_to=%2F&return_to=%2Fapprovals", "step_up=true"} {
		s := &stepupSessions{}
		h := SessionHandler{Origin: "https://console.invalid", Sessions: s}
		r := httptest.NewRequest("GET", "https://console.invalid/auth/step-up?"+query, nil)
		r.URL.Scheme, r.URL.Host = "", ""
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if strings.HasPrefix(query, "return_to=%2Fapprovals%2Frequest") {
			if w.Code != 303 || s.calls != 1 || s.path != "/approvals/request" || w.Header().Get("Location") != "https://issuer.invalid/auth" {
				t.Fatal(w.Code, s.calls)
			}
		} else if w.Code != 400 || s.calls != 0 {
			t.Fatal("arbitrary provider parameters accepted", query, w.Code)
		}
	}
}

func TestStepUpUnconfiguredServiceExplainsRemediation(t *testing.T) {
	h := SessionHandler{Origin: "https://console.invalid", Sessions: &transportSession{}}
	r := httptest.NewRequest("GET", "https://console.invalid/auth/step-up", nil)
	r.URL.Scheme, r.URL.Host = "", ""
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "ask your administrator") || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("unconfigured step-up lacked safe remediation", w.Code)
	}
}
