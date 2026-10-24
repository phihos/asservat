package browser

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type contentCredentialFixture struct {
	now    time.Time
	issuer string
	calls  int
	err    error
}

func (f *contentCredentialFixture) ObserveCredential(ctx context.Context, token string) (identities.CredentialObservation, error) {
	f.calls++
	if f.err != nil {
		return identities.CredentialObservation{}, f.err
	}
	if token != "synthetic" {
		return identities.CredentialObservation{}, identity.ErrDenied
	}
	p := identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}
	i := identity.Identity{Principal: identity.Principal{Issuer: f.issuer, Subject: "developer", ClientID: "native-client", Kind: identity.Human}, Policy: p, Scopes: []string{"evidence:read", "evidence:download"}, VerifiedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}
	return identities.CredentialObservation{Identity: i, Window: identities.CredentialWindow{IssuedAt: f.now, TokenExpiresAt: f.now.Add(time.Minute), GroupsExpireAt: f.now.Add(30 * time.Second), Policy: p, ObservedAt: f.now, FreshUntil: i.ValidUntil}}, ctx.Err()
}
func (f *contentCredentialFixture) Resolve(ctx context.Context, token string) (identity.Identity, error) {
	v, e := f.ObserveCredential(ctx, token)
	return v.Identity, e
}
func TestNativeContentAuthenticationKeepsOriginalCredentialAndNoGETRefresh(t *testing.T) {
	now := time.Now()
	credential := &contentCredentialFixture{now: now, issuer: "https://issuer.invalid"}
	sessions := &transportSession{now: now}
	h := &DownloadContentHandler{config: DownloadContentConfig{Issuer: credential.issuer, Now: func() time.Time { return now }}, sessions: SessionHandler{Sessions: sessions}, bearer: credential, credentials: credential}
	for _, mode := range []string{"bearer", "browser", "mixed", "duplicate", "cross-site", "wrong-issuer"} {
		t.Run(mode, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://console.invalid/api/v1/downloads/id/content", nil)
			r.Header.Set("Authorization", "Bearer synthetic")
			switch mode {
			case "browser":
				r.Header.Del("Authorization")
				r.Header.Set("Sec-Fetch-Site", "same-origin")
				r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
			case "mixed":
				r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
			case "duplicate":
				r.Header.Add("Authorization", "Bearer synthetic")
			case "cross-site":
				r.Header.Del("Authorization")
				r.Header.Set("Sec-Fetch-Site", "cross-site")
				r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
			case "wrong-issuer":
				credential.issuer = "https://wrong.invalid"
				defer func() { credential.issuer = h.config.Issuer }()
			}
			current, i, end, token, cookie, e := h.authenticate(t.Context(), r, now.Add(time.Hour))
			if mode == "browser" || mode == "bearer" {
				if e != nil || current == nil || !i.Valid(now) {
					t.Fatal(e)
				}
				if mode == "bearer" && (!end.Equal(now.Add(30*time.Second)) || token != "synthetic" || cookie != "") {
					t.Fatal("lost original bearer/group bound")
				}
				if mode == "browser" && (!end.Equal(now.Add(time.Hour)) || token != "" || cookie == "") {
					t.Fatal("session bounded to observation rather than original end")
				}
				if _, e = current.ResolveIdentity(t.Context()); e != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("ambiguous or foreign credential accepted")
			}
		})
	}
	if sessions.refreshes != 0 || sessions.csrf != 0 {
		t.Fatal("content GET rotated session")
	}
}
func TestNativeContentRoutingRejectsBeforeAuthority(t *testing.T) {
	h := &DownloadContentHandler{config: DownloadContentConfig{PublicOrigin: "https://console.invalid", Issuer: "https://issuer.invalid"}}
	for _, mode := range []string{"http", "host", "query", "encoded", "origin", "cross-site", "post", "body", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://console.invalid"+DownloadContentPrefix+"00000000-0000-4000-8000-000000000001/content", nil)
			r.URL.Scheme = ""
			r.URL.Host = ""
			switch mode {
			case "http":
				r.TLS = nil
			case "host":
				r.Host = "other.invalid"
			case "query":
				r.URL.RawQuery = "token=synthetic"
			case "encoded":
				r.URL.RawPath = "/encoded"
			case "origin":
				r.Header.Set("Origin", "https://other.invalid")
			case "cross-site":
				r.Header.Set("Sec-Fetch-Site", "cross-site")
			case "post":
				r.Method = "POST"
			case "body":
				r.ContentLength = 1
			case "unknown":
				r.URL.Path += "/extra"
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 {
				t.Fatal("invalid route reached authority")
			}
		})
	}
	r := httptest.NewRequest("GET", "https://console.invalid"+DownloadContentMetadataPath, nil)
	r.URL.Scheme = ""
	r.URL.Host = ""
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), h.config.Resource()) || strings.Contains(w.Body.String(), `/mcp`) {
		t.Fatal("wrong OAuth resource metadata")
	}
}
func TestNativeContentConditionalSelectionRequiresPositivePreflight(t *testing.T) {
	now := time.Now()
	m := artifact.NativeDownloadMetadata{Size: 17, ETag: `"exact"`, Filename: "context.json", SHA256: artifact.Digest{1}, ReadUntil: now.Add(time.Minute), DeleteBy: now.Add(time.Hour)}
	for _, code := range []int{304, 412, 416} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://console.invalid/native", nil)
			switch code {
			case 304:
				req.Header.Set("If-None-Match", m.ETag)
			case 412:
				req.Header.Set("If-Match", `"other"`)
			case 416:
				req.Header.Set("Range", "bytes=99-")
			}
			w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			f := &contentResponseFactory{writer: w, request: req}
			_, e := f.SelectDownloadResponse(m)
			if e == nil || DownloadConditionStatus(e) != code || w.Body.Len() != 0 || w.Header().Get("ETag") != "" {
				t.Fatal("selection disclosed metadata", e)
			}
			if e = f.conditional(t.Context(), code, time.Now); e == nil {
				t.Fatal("missing acknowledgement accepted")
			}
			f.DownloadContentPreflightComplete(now.Add(time.Second))
			if e = f.conditional(t.Context(), code, time.Now); e != nil {
				t.Fatal(e)
			}
			if w.Code != code || w.Body.Len() != 0 {
				t.Fatal("conditional wrote native body")
			}
		})
	}
	expired := &contentResponseFactory{writer: &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}, until: now.Add(-time.Second)}
	if e := expired.conditional(t.Context(), 304, time.Now); !errors.Is(e, artifact.ErrDownloadExpired) {
		t.Fatal("expired final preflight", e)
	}
}

func TestNativeContentDeniedReplyKeepsAuditBoundAndJoinsCancellation(t *testing.T) {
	until := time.Now().Add(time.Second)
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	if e := contentDeniedReply(t.Context(), w, until, time.Now); e != nil || w.Code != http.StatusForbidden || !w.until.Equal(until) {
		t.Fatal("denial lost original audit deadline", e)
	}
	expired := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	if e := contentDeniedReply(t.Context(), expired, time.Now().Add(-time.Second), time.Now); e == nil || expired.Body.Len() != 0 {
		t.Fatal("expired denial was written", e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	blocked := &contentDeniedCancellationWriter{ResponseRecorder: httptest.NewRecorder(), cancel: cancel, callback: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- contentDeniedReply(ctx, blocked, until, time.Now) }()
	select {
	case <-blocked.callback:
	case <-time.After(time.Second):
		t.Fatal("cancelled writer did not interrupt socket")
	}
	select {
	case <-done:
		t.Fatal("denial returned before cancellation callback joined")
	case <-time.After(20 * time.Millisecond):
	}
	close(blocked.release)
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled denial claimed success")
		}
	case <-time.After(time.Second):
		t.Fatal("denial did not join cancellation callback")
	}
}

type contentDeniedCancellationWriter struct {
	*httptest.ResponseRecorder
	cancel            context.CancelFunc
	callback, release chan struct{}
	calls             atomic.Int32
}

func (w *contentDeniedCancellationWriter) SetWriteDeadline(time.Time) error {
	if w.calls.Add(1) == 2 {
		close(w.callback)
		<-w.release
	}
	return nil
}
func (w *contentDeniedCancellationWriter) WriteHeader(code int) {
	w.ResponseRecorder.WriteHeader(code)
	w.cancel()
	<-w.callback
}

func TestNativeContentCredentialOutageIsNotInvalidCredential(t *testing.T) {
	credential := &contentCredentialFixture{err: identity.ErrUnavailable}
	h := &DownloadContentHandler{config: DownloadContentConfig{Now: time.Now}, credentials: credential}
	r := httptest.NewRequest(http.MethodGet, "https://console.invalid/native", nil)
	r.Header.Set("Authorization", "Bearer synthetic")
	if _, _, _, _, _, e := h.authenticate(t.Context(), r, time.Now().Add(time.Minute)); !errors.Is(e, identity.ErrUnavailable) {
		t.Fatal("credential observation outage changed to authentication denial", e)
	}
}

type contentSocketRecorder struct{ *httptest.ResponseRecorder }

func (contentSocketRecorder) SetReadDeadline(time.Time) error  { return nil }
func (contentSocketRecorder) SetWriteDeadline(time.Time) error { return nil }

// Installed native91 answered the content GET with a bare 503 and no log line.
// Every unavailable reply now names its closed stage for the operator report.
func TestNativeContentUnavailableNamesItsStage(t *testing.T) {
	credential := &contentCredentialFixture{err: identity.ErrUnavailable}
	h := &DownloadContentHandler{config: DownloadContentConfig{PublicOrigin: "https://console.invalid", Issuer: "https://issuer.invalid", Now: time.Now}, credentials: credential, slots: make(chan struct{}, 1), active: map[identity.Principal]int{}}
	var steps []string
	h.Refused = func(_ context.Context, operation string, err error) {
		var fixed interface{ FixedStep() string }
		if !errors.As(err, &fixed) || !errors.Is(err, identity.ErrUnavailable) {
			t.Fatal("refusal lost its stage or cause", err)
		}
		steps = append(steps, operation+"/"+fixed.FixedStep())
	}
	r := httptest.NewRequest(http.MethodGet, DownloadContentPrefix+"00000000-0000-4000-8000-000000000001/content", nil)
	r.Host, r.TLS = "console.invalid", &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer synthetic")
	w := contentSocketRecorder{httptest.NewRecorder()}
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || len(steps) != 1 || steps[0] != "content/authenticate" {
		t.Fatal("unavailable content reply did not name its stage", w.Code, steps)
	}
}
