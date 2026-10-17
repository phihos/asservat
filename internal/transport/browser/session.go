package browser

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/identity"
)

const SessionCookie = "__Host-asservat-session"
const loginCookie = "__Host-asservat-login"

type SessionService interface {
	Begin(context.Context, string) (app.LoginRedirect, error)
	Complete(context.Context, string, string, string) (app.LoginResult, error)
	Resolve(context.Context, string, bool) (app.SessionView, error)
	CSRF(context.Context, string) (string, error)
	CheckCSRF(context.Context, string, string) error
	End(context.Context, string) error
	BackchannelLogout(context.Context, string) error
}

// SessionHandler has no default authority or forwarded-header trust. Bootstrap
// supplies the exact public HTTPS origin and a current session service.
type SessionHandler struct {
	Origin, Issuer string
	Sessions       SessionService
}

func (h SessionHandler) validOrigin() bool {
	u, e := url.Parse(h.Origin)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}
func (h SessionHandler) base(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	if h.Sessions == nil || !h.validOrigin() {
		sessionProblem(w, 503)
		return false
	}
	u, _ := url.Parse(h.Origin)
	if r.TLS == nil || r.Host != u.Host || r.URL.IsAbs() || len(r.RequestURI) > 8192 || r.Header.Get("Authorization") != "" {
		sessionProblem(w, 400)
		return false
	}
	return true
}
func cookieValue(r *http.Request, name string) (string, error) {
	var value string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			value = c.Value
			count++
		}
	}
	if count != 1 || len(value) != 43 {
		return "", identity.ErrDenied
	}
	return value, nil
}
func setSessionCookie(w http.ResponseWriter, name, value string, until time.Time) {
	sameSite := http.SameSiteStrictMode
	if name == loginCookie {
		sameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Expires: until, Secure: true, HttpOnly: true, SameSite: sameSite})
}
func clearSessionCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
func sessionProblem(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/problem+json")
	if status == 503 || status == http.StatusConflict {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status})
}
func sessionFailure(w http.ResponseWriter, err error) {
	status := 503
	if errors.Is(err, identity.ErrSessionBusy) {
		status = http.StatusConflict
	} else if errors.Is(err, identity.ErrDenied) {
		status = 401
	} else if errors.Is(err, identity.ErrInvalid) {
		status = 400
	} else if errors.Is(err, identity.ErrSessionCapacity) {
		status = 429
	}
	sessionProblem(w, status)
}
func sessionJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (h SessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.base(w, r) {
		return
	}
	switch r.URL.Path {
	case "/auth/login":
		if r.Method != "GET" {
			sessionProblem(w, 405)
			return
		}
		q, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil || len(q) > 1 || len(q["return_to"]) > 1 {
			sessionProblem(w, 400)
			return
		}
		for k := range q {
			if k != "return_to" {
				sessionProblem(w, 400)
				return
			}
		}
		path := q.Get("return_to")
		if path == "" {
			path = "/"
		}
		v, e := h.Sessions.Begin(r.Context(), path)
		if e != nil {
			sessionFailure(w, e)
			return
		}
		setSessionCookie(w, loginCookie, v.Browser, v.ExpiresAt)
		http.Redirect(w, r, v.URL, http.StatusSeeOther)
	case "/auth/callback":
		if r.Method != "GET" {
			sessionProblem(w, 405)
			return
		}
		q, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil {
			sessionProblem(w, 400)
			return
		}
		for k, v := range q {
			if len(v) != 1 || k != "state" && k != "code" && k != "iss" && k != "session_state" {
				sessionProblem(w, 400)
				return
			}
		}
		// The first qualified provider emits the authorization response issuer.
		if q.Get("iss") != h.Issuer || q.Get("code") == "" || q.Get("state") == "" {
			sessionProblem(w, 400)
			return
		}
		cookie, e := cookieValue(r, loginCookie)
		if e != nil {
			sessionFailure(w, e)
			return
		}
		result, e := h.Sessions.Complete(r.Context(), q.Get("state"), cookie, q.Get("code"))
		clearSessionCookie(w, loginCookie)
		if e != nil {
			sessionFailure(w, e)
			return
		}
		if !app.LocalReturnPath(result.ReturnTo) {
			sessionProblem(w, 500)
			return
		}
		setSessionCookie(w, SessionCookie, result.Cookie, result.Session.ExpiresAt)
		http.Redirect(w, r, result.ReturnTo, http.StatusSeeOther)
	case "/auth/backchannel-logout":
		media, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if r.Method != "POST" || mediaErr != nil || media != "application/x-www-form-urlencoded" {
			sessionProblem(w, 400)
			return
		}
		b, e := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if e != nil || len(b) == 64<<10 {
			sessionProblem(w, 400)
			return
		}
		defer clear(b)
		q, e := url.ParseQuery(string(b))
		if e != nil || len(q) > 128 || len(q["logout_token"]) != 1 {
			sessionProblem(w, 400)
			return
		}
		if e = h.Sessions.BackchannelLogout(r.Context(), q.Get("logout_token")); e != nil {
			sessionFailure(w, e)
			return
		}
		w.WriteHeader(200)
	case "/auth/csrf", "/api/v1/session":
		if r.Method != "GET" || r.URL.RawQuery != "" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			sessionProblem(w, 400)
			return
		}
		cookie, e := cookieValue(r, SessionCookie)
		if e != nil {
			sessionFailure(w, e)
			return
		}
		if r.URL.Path == "/auth/csrf" {
			v, e := h.Sessions.CSRF(r.Context(), cookie)
			if e != nil {
				sessionFailure(w, e)
				return
			}
			sessionJSON(w, map[string]string{"csrf_token": v})
			return
		}
		v, e := h.Sessions.Resolve(r.Context(), cookie, false)
		if e != nil {
			sessionFailure(w, e)
			return
		}
		writeSession(w, v)
	case "/auth/refresh", "/auth/logout":
		if r.Method != "POST" || r.URL.RawQuery != "" {
			sessionProblem(w, 405)
			return
		}
		if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
			sessionProblem(w, 400)
			return
		}
		cookie, e := h.checkMutation(r)
		if e != nil {
			if errors.Is(e, identity.ErrDenied) {
				sessionProblem(w, 403)
			} else {
				sessionFailure(w, e)
			}
			return
		}
		if r.URL.Path == "/auth/logout" {
			if e = h.Sessions.End(r.Context(), cookie); e != nil {
				// Retryable Busy means the CSRF precondition rejected the
				// request before End. Once revocation starts its outcome can
				// be uncertain; never invite an automatic POST replay.
				if errors.Is(e, identity.ErrSessionBusy) {
					sessionProblem(w, http.StatusServiceUnavailable)
				} else {
					sessionFailure(w, e)
				}
				return
			}
			clearSessionCookie(w, SessionCookie)
			w.WriteHeader(204)
			return
		}
		v, e := h.Sessions.Resolve(r.Context(), cookie, true)
		if e != nil {
			sessionFailure(w, e)
			return
		}
		writeSession(w, v)
	default:
		sessionProblem(w, 404)
	}
}
func (h SessionHandler) checkMutation(r *http.Request) (string, error) {
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != h.Origin || len(r.Header.Values("X-CSRF-Token")) != 1 || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return "", identity.ErrDenied
	}
	c, e := cookieValue(r, SessionCookie)
	if e != nil {
		return "", e
	}
	if e = h.Sessions.CheckCSRF(r.Context(), c, r.Header.Get("X-CSRF-Token")); e != nil {
		return "", e
	}
	return c, nil
}
func writeSession(w http.ResponseWriter, v app.SessionView) {
	// Roles are target-specific permissions; no role is inferred from identity
	// groups. A login or refresh is never an approval step-up.
	sessionJSON(w, map[string]any{"principal": map[string]string{"issuer": v.Identity.Principal.Issuer, "subject_id": v.Identity.Principal.Subject, "kind": "user"}, "roles": []string{}, "csrf_token": v.CSRF, "expires_at": v.ExpiresAt.UTC().Format(time.RFC3339Nano), "step_up": "unavailable"})
}

// Authenticate is the ingress facet for separately authorized application
// operations. No generic proxy or implicit collection endpoint is exposed.
func (h SessionHandler) Authenticate(w http.ResponseWriter, r *http.Request) (app.SessionView, error) {
	c, mutating, e := h.authenticateCookie(w, r)
	if e != nil {
		return app.SessionView{}, e
	}
	return h.Sessions.Resolve(r.Context(), c, mutating)
}

// AuthenticateCurrent binds subsequent application authorization to this exact
// HTTP request and current server-side session. Only the ingress may refresh;
// no provider credential or indefinitely reusable identity leaves the service.
func (h SessionHandler) AuthenticateCurrent(w http.ResponseWriter, r *http.Request) (app.CurrentIdentity, app.SessionView, error) {
	c, mutating, e := h.authenticateCookie(w, r)
	if e != nil {
		return nil, app.SessionView{}, e
	}
	return app.NewBrowserRequest(r.Context(), h.Sessions, c, mutating, time.Now)
}

func (h SessionHandler) authenticateCookie(w http.ResponseWriter, r *http.Request) (string, bool, error) {
	if !h.base(w, r) {
		return "", false, identity.ErrDenied
	}
	c, e := cookieValue(r, SessionCookie)
	if e != nil {
		return "", false, e
	}
	mutating := r.Method != "GET" && r.Method != "HEAD"
	if mutating {
		c, e = h.checkMutation(r)
		if e != nil {
			return "", false, e
		}
	}
	if strings.Contains(r.URL.RawQuery, "access_token") {
		return "", false, identity.ErrInvalid
	}
	return c, mutating, nil
}
