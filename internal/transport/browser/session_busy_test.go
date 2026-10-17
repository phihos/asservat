package browser

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	value "asservat.local/asservat/internal/domain/identity"
)

type logoutBusySession struct {
	SessionService
	checkErr, endErr error
	ends             int
}

func (s *logoutBusySession) CheckCSRF(context.Context, string, string) error { return s.checkErr }
func (s *logoutBusySession) End(context.Context, string) error {
	s.ends++
	return s.endErr
}

func TestLogoutBusyOnlyBeforeRevocation(t *testing.T) {
	for _, tc := range []struct {
		name             string
		checkErr, endErr error
		status, ends     int
		retry            string
	}{
		{"CSRF rotation before revocation", value.ErrSessionBusy, nil, 409, 0, "1"},
		{"uncertain revocation cannot be retried", nil, value.ErrSessionBusy, 503, 1, "1"},
		{"failed revocation cannot be retried", nil, value.ErrUnavailable, 503, 1, "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &logoutBusySession{checkErr: tc.checkErr, endErr: tc.endErr}
			h := SessionHandler{Origin: "https://console.invalid", Sessions: s}
			r := httptest.NewRequest("POST", h.Origin+"/auth/logout", nil)
			r.URL.Scheme, r.URL.Host = "", ""
			r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
			r.Header.Set("Origin", h.Origin)
			r.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || s.ends != tc.ends || w.Header().Get("Retry-After") != tc.retry || w.Header().Get("Set-Cookie") != "" {
				t.Fatalf("logout effect boundary lost: status=%d ends=%d headers=%v", w.Code, s.ends, w.Header())
			}
		})
	}
}

func TestSessionBusyIsTemporaryWithoutCookieRemovalOrRedirect(t *testing.T) {
	w := httptest.NewRecorder()
	sessionFailure(w, errors.Join(errors.New("private provider diagnostic"), value.ErrSessionBusy))
	if w.Code != http.StatusConflict || w.Header().Get("Retry-After") != "1" || w.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("busy lost typed retry contract: %d %#v", w.Code, w.Header())
	}
	if w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" || w.Body.String() != `{"status":409,"title":"Conflict","type":"about:blank"}`+"\n" {
		t.Fatalf("busy changed credentials or leaked diagnostics: %#v %s", w.Header(), w.Body.String())
	}
}
