package browser

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

const DownloadContentPrefix = "/api/v1/downloads/"
const DownloadContentMetadataPath = "/.well-known/oauth-protected-resource/downloads"

var ErrDownloadContentConfiguration = errors.New("invalid native content configuration")

// contentConfigurationStep is ErrDownloadContentConfiguration naming the
// closed check that refused it, for startup diagnostics.
type contentConfigurationStep string

func (s contentConfigurationStep) Error() string     { return ErrDownloadContentConfiguration.Error() }
func (s contentConfigurationStep) Unwrap() error     { return ErrDownloadContentConfiguration }
func (s contentConfigurationStep) FixedStep() string { return "content-" + string(s) }

// Protected installation input. Bearer verification must be pinned to Resource
// and Issuer independently of the MCP resource. No forwarded-header trust.
type DownloadContentConfig struct {
	PublicOrigin, Issuer          string
	MaxConcurrent, MaxPerIdentity int
	MaxDuration                   time.Duration
	Now                           func() time.Time
	NewID                         func() string
}

func (c DownloadContentConfig) Resource() string { return c.PublicOrigin + "/api/v1/downloads" }

type DownloadContentHandler struct {
	config      DownloadContentConfig
	sessions    SessionHandler
	bearer      identities.Resolver
	credentials identities.CredentialObserver
	pauses      identities.BrowserRefreshPauseReader
	audit       *presentation.AuditedOperations
	runtime     *evidence.ContextNativeRuntime
	transfer    evidence.DownloadResponseTransfer
	slots       chan struct{}
	mu          sync.Mutex
	active      map[identity.Principal]int
}

func NewDownloadContentHandler(c DownloadContentConfig, sessions SessionHandler, bearer identities.Resolver, pauses identities.BrowserRefreshPauseReader, audit *presentation.AuditedOperations, runtime *evidence.ContextNativeRuntime, transfer evidence.DownloadResponseTransfer) (*DownloadContentHandler, error) {
	issuer, e := url.Parse(c.Issuer)
	credential, ok := bearer.(identities.CredentialObserver)
	switch {
	case e != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || c.Now == nil || c.NewID == nil || c.MaxConcurrent < 1 || c.MaxConcurrent > 16 || c.MaxPerIdentity < 1 || c.MaxPerIdentity > c.MaxConcurrent || c.MaxDuration <= 0 || c.MaxDuration > 8*time.Hour:
		return nil, contentConfigurationStep("config")
	case !sessions.validOrigin() || sessions.Origin != c.PublicOrigin || sessions.Issuer != c.Issuer || sessions.Sessions == nil:
		return nil, contentConfigurationStep("sessions")
	case bearer == nil || !ok || pauses == nil:
		return nil, contentConfigurationStep("identity")
	case audit == nil || audit.PublicOrigin() != c.PublicOrigin:
		return nil, contentConfigurationStep("audit")
	case !runtime.Configured():
		return nil, contentConfigurationStep("runtime")
	case !transfer.Configured():
		return nil, contentConfigurationStep("transfer")
	}
	if _, ok := transfer.Responses.(interface{ FirstContextResponsesOnly() }); !ok {
		return nil, contentConfigurationStep("responses")
	}
	// Check the healthy shared owner without admitting an operation.
	if _, e = presentation.NewNativeContentAuditor(audit, presentation.NativeContentInput{DownloadID: "00000000-0000-4000-8000-000000000001"}, c.Now().Add(time.Second)); e != nil {
		return nil, contentConfigurationStep("auditor")
	}
	return &DownloadContentHandler{config: c, sessions: sessions, bearer: bearer, credentials: credential, pauses: pauses, audit: audit, runtime: runtime, transfer: transfer, slots: make(chan struct{}, c.MaxConcurrent), active: make(map[identity.Principal]int)}, nil
}
func (h *DownloadContentHandler) acquire(p identity.Principal) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active[p] >= h.config.MaxPerIdentity {
		return false
	}
	h.active[p]++
	return true
}
func (h *DownloadContentHandler) release(p identity.Principal) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.active[p]--
	if h.active[p] == 0 {
		delete(h.active, p)
	}
}
func (h *DownloadContentHandler) challenge(w http.ResponseWriter, status int) {
	w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+h.config.PublicOrigin+DownloadContentMetadataPath+`"`)
	sessionProblem(w, status)
}
func (h *DownloadContentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	origin, _ := url.Parse(h.config.PublicOrigin)
	if r.TLS == nil || r.Host != origin.Host || r.URL.IsAbs() || r.URL.RawQuery != "" || r.URL.RawPath != "" || len(r.RequestURI) > 4096 || len(r.Header.Values("Origin")) > 1 || r.Header.Get("Origin") != "" && r.Header.Get("Origin") != h.config.PublicOrigin || len(r.Header.Values("Sec-Fetch-Site")) > 1 || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		sessionProblem(w, 403)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		sessionProblem(w, 405)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Header.Values("Content-Encoding")) != 0 {
		sessionProblem(w, 400)
		return
	}
	if r.URL.Path == DownloadContentMetadataPath {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Resource string   `json:"resource"`
			Servers  []string `json:"authorization_servers"`
			Scopes   []string `json:"scopes_supported"`
			Methods  []string `json:"bearer_methods_supported"`
		}{h.config.Resource(), []string{h.config.Issuer}, []string{"evidence:read", "evidence:download"}, []string{"header"}})
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, DownloadContentPrefix), "/content")
	if !authorization.UUID(id) || r.URL.Path != DownloadContentPrefix+id+"/content" {
		sessionProblem(w, 404)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		sessionProblem(w, 429)
		return
	}
	started := h.config.Now()
	preflightUntil := started.Add(5 * time.Second)
	initial, end := context.WithDeadline(r.Context(), preflightUntil)
	defer end()
	control := http.NewResponseController(w)
	if control.SetReadDeadline(preflightUntil) != nil || control.SetWriteDeadline(preflightUntil) != nil {
		sessionProblem(w, 503)
		return
	}
	if r.Body != nil {
		b, e := io.ReadAll(io.LimitReader(r.Body, 1))
		_ = r.Body.Close()
		if e != nil || len(b) != 0 {
			sessionProblem(w, 400)
			return
		}
	}
	current, i, hardUntil, token, cookie, err := h.authenticate(initial, r, started.Add(h.config.MaxDuration))
	if err != nil {
		if errors.Is(err, identity.ErrDenied) || errors.Is(err, identity.ErrInvalid) {
			h.challenge(w, 401)
		} else {
			sessionProblem(w, 503)
		}
		return
	}
	if !h.acquire(i.Principal) {
		sessionProblem(w, 429)
		return
	}
	defer h.release(i.Principal)
	preflightUntil = identity.Earlier(preflightUntil, i.ValidUntil)
	if !slices.Contains(i.Scopes, "evidence:read") || !slices.Contains(i.Scopes, "evidence:download") {
		bound, e := h.audit.RejectBeforeDispatch(initial, current, presentation.IngressRejection{RequestedOperation: "download_artifact_content", Kind: presentation.IngressDenied})
		if e != nil || initial.Err() != nil || !h.config.Now().Before(bound) {
			sessionProblem(w, 503)
			return
		}
		if e = contentDeniedReply(initial, w, identity.Earlier(bound, preflightUntil), h.config.Now); e != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}
	owner, cancel := context.WithDeadline(r.Context(), hardUntil)
	defer cancel()
	owner, release, err := h.runtime.BeginContent(owner, id, i.Principal)
	if err != nil {
		sessionProblem(w, 503)
		return
	}
	defer release()
	var reader identities.ReaderIdentity
	if cookie != "" {
		reader, err = identities.NewBrowserRefreshReader(owner, h.sessions.Sessions, h.pauses, cookie, i.Principal, hardUntil, h.config.Now)
	} else {
		reader, err = identities.NewBearerLiveReader(owner, contentPinnedResolver{h}, token, i.Principal, hardUntil, h.config.Now)
	}
	token = ""
	cookie = ""
	if err != nil || initial.Err() != nil || !h.config.Now().Before(preflightUntil) {
		if reader != nil {
			reader.Close()
		}
		sessionProblem(w, 503)
		return
	}
	defer reader.Close()
	source, err := evidence.NewContextNativeResponse(owner, h.runtime)
	if err != nil {
		sessionProblem(w, 503)
		return
	}
	defer source.Close()
	audit, err := presentation.NewNativeContentAuditor(h.audit, presentation.NativeContentInput{DownloadID: id, IfMatch: r.Header.Values("If-Match"), IfNoneMatch: r.Header.Values("If-None-Match"), IfRange: r.Header.Values("If-Range"), Range: r.Header.Values("Range")}, preflightUntil)
	if err != nil {
		sessionProblem(w, 503)
		return
	}
	factory := &contentResponseFactory{writer: w, request: r.WithContext(owner)}
	request := evidence.DownloadResponseRequest{SessionID: id, ResponseID: h.config.NewID(), OwnerID: h.config.NewID(), HardUntil: hardUntil}
	err = h.transfer.TransferAudited(owner, reader, request, source, factory, audit)
	if err == nil {
		return
	}
	// Transfer's defers have joined every regional read, write and SQL close.
	if factory.sent() {
		panic(http.ErrAbortHandler)
	}
	status := DownloadConditionStatus(err)
	if status != http.StatusInternalServerError && !factory.until.IsZero() && owner.Err() == nil && h.config.Now().Before(factory.until) {
		if e := factory.conditional(owner, status, h.config.Now); e != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}
	sessionProblem(w, 503)
}
func (h *DownloadContentHandler) authenticate(ctx context.Context, r *http.Request, hard time.Time) (identities.CurrentIdentity, identity.Identity, time.Time, string, string, error) {
	var zero identity.Identity
	if len(r.Header.Values("Authorization")) != 0 {
		if len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("Cookie")) != 0 {
			return nil, zero, time.Time{}, "", "", identity.ErrDenied
		}
		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || len(fields[1]) > 16<<10 {
			return nil, zero, time.Time{}, "", "", identity.ErrDenied
		}
		token := fields[1]
		v, e := h.credentials.ObserveCredential(ctx, token)
		if e != nil {
			return nil, zero, time.Time{}, "", "", e
		}
		if !v.Identity.Valid(h.config.Now()) || !v.Window.Valid(h.config.Now()) || v.Window.Policy != v.Identity.Policy || v.Window.FreshUntil.After(v.Identity.ValidUntil) || v.Identity.Principal.Issuer != h.config.Issuer {
			return nil, zero, time.Time{}, "", "", identity.ErrDenied
		}
		hard = identity.Earlier(hard, identity.Earlier(v.Window.TokenExpiresAt, v.Window.GroupsExpireAt))
		current, i, e := identities.NewBearerRequest(ctx, contentPinnedResolver{h}, token, h.config.Now)
		if e == nil && i.Principal != v.Identity.Principal {
			e = identity.ErrDenied
		}
		return current, i, hard, token, "", e
	}
	if len(r.Header.Values("Sec-Fetch-Site")) != 1 || r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		return nil, zero, time.Time{}, "", "", identity.ErrDenied
	}
	cookie, e := cookieValue(r, SessionCookie)
	if e != nil {
		return nil, zero, time.Time{}, "", "", e
	}
	current, v, e := identities.NewBrowserRequest(ctx, h.sessions.Sessions, cookie, false, h.config.Now)
	if e == nil && v.Identity.Principal.Issuer != h.config.Issuer {
		e = identity.ErrDenied
	}
	return current, v.Identity, identity.Earlier(hard, v.ExpiresAt), "", cookie, e
}

type contentPinnedResolver struct{ handler *DownloadContentHandler }

func (p contentPinnedResolver) Resolve(ctx context.Context, token string) (identity.Identity, error) {
	i, e := p.handler.bearer.Resolve(ctx, token)
	if e != nil {
		return identity.Identity{}, e
	}
	if ctx.Err() != nil || !i.Valid(p.handler.config.Now()) || i.Principal.Issuer != p.handler.config.Issuer {
		return identity.Identity{}, identity.ErrDenied
	}
	return i, nil
}

type contentResponseFactory struct {
	writer    http.ResponseWriter
	request   *http.Request
	metadata  artifact.NativeDownloadMetadata
	until     time.Time
	bodyUntil time.Time
	sink      *HTTPDownloadResponse
}

func (f *contentResponseFactory) SelectDownloadResponse(m artifact.NativeDownloadMetadata) (artifact.DownloadSelection, error) {
	f.metadata = m
	selected, e := ResolveDownloadSelection(m.Size, m.ETag, f.request.Header)
	if e == nil {
		return selected, nil
	}
	status := evidence.DownloadContentInvalid
	switch DownloadConditionStatus(e) {
	case 304:
		status = evidence.DownloadContentNotModified
	case 412:
		status = evidence.DownloadContentPrecondition
	case 416:
		status = evidence.DownloadContentRange
	}
	return selected, &evidence.DownloadContentSelectionError{Status: status, Cause: e}
}
func (f *contentResponseFactory) OpenDownloadResponse(ctx context.Context, m artifact.NativeDownloadMetadata, r artifact.DownloadResponse) (evidence.DownloadResponseSink, error) {
	if ctx.Err() != nil || f.bodyUntil.IsZero() || r.Until.After(f.bodyUntil) {
		return nil, artifact.ErrDownloadExpired
	}
	sink, e := NewHTTPDownloadResponse(f.writer, f.request, m, r)
	if e == nil {
		f.sink = sink
	}
	return sink, e
}
func (f *contentResponseFactory) DownloadContentPreflightComplete(until time.Time) { f.until = until }

// Re-arm only after acknowledged preflight, before its existing deadline can
// expire. HTTP/2 resets an expired stream even if no body write has started.
// This idle bound cannot authorize bytes or extend any original response end.
func (f *contentResponseFactory) BeginDownloadContentBody(ctx context.Context, until time.Time) error {
	now := time.Now()
	if ctx == nil || ctx.Err() != nil || f.request == nil || f.request.Context().Err() != nil || !f.bodyUntil.IsZero() || f.sink != nil || !now.Before(f.until) || !now.Before(until) {
		return artifact.ErrDownloadExpired
	}
	for _, owner := range []context.Context{ctx, f.request.Context()} {
		if d, ok := owner.Deadline(); ok {
			until = identity.Earlier(until, d)
		}
	}
	if !now.Before(until) {
		return artifact.ErrDownloadExpired
	}
	control := http.NewResponseController(f.writer)
	if e := control.SetWriteDeadline(until); e != nil {
		return e
	}
	if ctx.Err() != nil || f.request.Context().Err() != nil || !time.Now().Before(f.until) || !time.Now().Before(until) {
		_ = control.SetWriteDeadline(time.Now())
		return artifact.ErrDownloadExpired
	}
	f.bodyUntil = until
	return nil
}

func (f *contentResponseFactory) sent() bool { return f.sink != nil && f.sink.HeadersSent() }
func (f *contentResponseFactory) conditional(owner context.Context, status int, now func() time.Time) error {
	ctx, cancel := context.WithDeadline(owner, f.until)
	defer cancel()
	control := http.NewResponseController(f.writer)
	if ctx.Err() != nil || !now().Before(f.until) || control.SetWriteDeadline(f.until) != nil {
		return artifact.ErrDownloadExpired
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = control.SetWriteDeadline(time.Now()); close(joined) })
	defer func() {
		if !stop() {
			<-joined
		}
	}()
	if ctx.Err() != nil {
		return artifact.ErrDownloadExpired
	}
	if status == 304 {
		f.writer.Header().Set("ETag", f.metadata.ETag)
	}
	if status == 416 {
		f.writer.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(f.metadata.Size, 10))
	}
	f.writer.WriteHeader(status)
	if e := control.Flush(); e != nil {
		return e
	}
	if ctx.Err() != nil || !now().Before(f.until) {
		return artifact.ErrDownloadExpired
	}
	return nil
}

// Even an acknowledged scope denial retains the original current/audit bound
// through the actual socket write. A callback cannot survive handler cleanup.
func contentDeniedReply(owner context.Context, w http.ResponseWriter, until time.Time, now func() time.Time) error {
	ctx, cancel := context.WithDeadline(owner, until)
	defer cancel()
	control := http.NewResponseController(w)
	if ctx.Err() != nil || !now().Before(until) || control.SetWriteDeadline(until) != nil {
		return artifact.ErrDownloadExpired
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = control.SetWriteDeadline(time.Now()); close(joined) })
	defer func() {
		if !stop() {
			<-joined
		}
	}()
	if ctx.Err() != nil {
		return artifact.ErrDownloadExpired
	}
	sessionProblem(w, http.StatusForbidden)
	if e := control.Flush(); e != nil {
		return e
	}
	if ctx.Err() != nil || !now().Before(until) {
		return artifact.ErrDownloadExpired
	}
	return nil
}
