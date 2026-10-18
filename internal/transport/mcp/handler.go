// Package mcp provides the authenticated, bounded MCP HTTP boundary. It has no
// database/key access and cannot grant collection or disclosure authority.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	identity "asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	Path             = "/mcp"
	MetadataPath     = "/.well-known/oauth-protected-resource/mcp"
	MaxRequestBytes  = 32 << 10
	MaxResponseBytes = 64 << 10
	maxNesting       = 32
	requestLifetime  = 5 * time.Second
)

var ErrConfiguration = errors.New("invalid MCP configuration")

// Config comes from protected installation configuration, never an HTTP caller.
// The resolver MUST use an access-token verifier pinned to Resource() as audience
// and to Issuer, and current organization/client policy. A browser-session
// resolver, ID-token verifier or caller-selected issuer cannot implement it.
// This boundary currently accepts direct TLS only; forwarded headers confer no
// transport trust. Gateway termination needs a separately qualified adapter.
type Config struct {
	PublicOrigin   string
	Issuer         string
	Version        string
	MaxConcurrent  int
	MaxPerIdentity int
}

func (c Config) Resource() string { return c.PublicOrigin + Path }

type Handler struct {
	config       Config
	identities   identities.Resolver
	protocol     http.Handler
	slots        chan struct{}
	normalWork   chan struct{}
	stopWork     chan struct{}
	stopFlight   map[identity.Principal]int
	normalFlight map[identity.Principal]int
	wire         *contracts.InvestigationContracts
	mu           sync.Mutex
	inFlight     map[identity.Principal]int
	now          func() time.Time
	operations   presentation.Operations
	audited      *presentation.AuditedOperations
	security     presentation.IngressCounters
	// Report, when set before serving, receives a closed reason for each 503;
	// it carries no request content. The
	// installed journey's first MCP call ended in a bare 503. Diagnostics only.
	Report func(reason string)
}

// unavailable answers 503 and reports its closed reason.
func (h *Handler) unavailable(w http.ResponseWriter, reason string) {
	if h.Report != nil {
		h.Report(reason)
	}
	problem(w, http.StatusServiceUnavailable)
}

func NewHandler(c Config, resolver identities.Resolver) (*Handler, error) {
	return newHandler(c, resolver, nil, nil)
}

// NewContextHandler is an unaudited component/test constructor. It must not
// be used for an enabled runtime. NewAuditedContextHandler composes ingress and
// dispatched operations through the exact same audit owner. Both remain inert
// until protected bootstrap qualifies and mounts the listener.
func NewContextHandler(c Config, resolver identities.Resolver, operations presentation.Operations) (*Handler, error) {
	if operations == nil || operations.PublicOrigin() != c.PublicOrigin {
		return nil, ErrConfiguration
	}
	return newHandler(c, resolver, operations, nil)
}

// NewAuditedContextHandler requires one concrete audit owner for both SDK
// callbacks and rejections that the SDK raises before those callbacks.
func NewAuditedContextHandler(c Config, resolver identities.Resolver, operations *presentation.AuditedOperations) (*Handler, error) {
	if operations == nil || operations.PublicOrigin() != c.PublicOrigin {
		return nil, ErrConfiguration
	}
	return newHandler(c, resolver, operations, operations)
}
func (h *Handler) SecurityCounters() presentation.IngressSecuritySnapshot {
	return h.security.Snapshot()
}

type operationIdentityKey struct{}
type operationDeadlineKey struct{}

// SDK callbacks may run in a different goroutine. This state belongs to one
// authenticated HTTP request and can only shorten its original delivery fence.
// It is never supplied by tool input, serialized, persisted or reused.
type operationDeadline struct {
	mu      sync.Mutex
	until   time.Time
	invalid bool
	// failure names a failed operation call for the 503 report: the tool
	// name and a closed class, never request content.
	failure string
	reply   *presentation.OperationReply
	closed  bool
}

func (d *operationDeadline) retain(reply presentation.OperationReply) bool {
	d.mu.Lock()
	if d.closed || d.reply != nil {
		d.mu.Unlock()
		_ = reply.Close(context.Background())
		clear(reply.Body)
		return false
	}
	d.reply = &reply
	d.mu.Unlock()
	return true
}
func (d *operationDeadline) check(ctx context.Context) error {
	d.mu.Lock()
	reply, closed := d.reply, d.closed
	d.mu.Unlock()
	if closed {
		return presentation.ErrOperationDelivery
	}
	if reply == nil {
		return nil
	}
	return reply.CheckDisclosure(ctx)
}
func (d *operationDeadline) close(ctx context.Context) {
	d.mu.Lock()
	d.closed = true
	reply := d.reply
	d.mu.Unlock()
	if reply != nil {
		_ = reply.Close(ctx)
		clear(reply.Body)
	}
}

func (d *operationDeadline) responseContext(ctx context.Context) (context.Context, context.CancelFunc) {
	d.mu.Lock()
	reply, closed := d.reply, d.closed
	d.mu.Unlock()
	if closed {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		return canceled, cancel
	}
	if reply == nil {
		return ctx, func() {}
	}
	return reply.ResponseContext(ctx)
}

func (d *operationDeadline) fail(reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failure == "" {
		d.failure = reason
	}
}
func (d *operationDeadline) failed() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.failure
}

func (d *operationDeadline) restrict(until time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if until.IsZero() {
		d.invalid = true
		return false
	}
	if until.Before(d.until) {
		d.until = until
	}
	return !d.invalid
}
func (d *operationDeadline) current(now time.Time) (time.Time, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.until, !d.invalid && !d.until.IsZero() && now.Before(d.until)
}

func newHandler(c Config, resolver identities.Resolver, operations presentation.Operations, audited *presentation.AuditedOperations) (*Handler, error) {
	origin, err := url.Parse(c.PublicOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.Opaque != "" || !identity.Text(c.PublicOrigin, 2048) || resolver == nil || !identity.Text(c.Version, 64) || c.MaxConcurrent < 1 || c.MaxConcurrent > 64 || c.MaxPerIdentity < 1 || c.MaxPerIdentity > 4 || c.MaxPerIdentity > c.MaxConcurrent {
		return nil, ErrConfiguration
	}
	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || issuer.Opaque != "" || !identity.Text(c.Issuer, 2048) {
		return nil, ErrConfiguration
	}
	// No tool is registered until its shared application service and canonical
	// schemas are implemented. Empty discovery is deliberate: the design catalog
	// is not a capability claim. No prompts/resources/logging or client callbacks.
	server := sdk.NewServer(&sdk.Implementation{Name: "Asservat", Version: c.Version}, &sdk.ServerOptions{
		Capabilities:              &sdk.ServerCapabilities{},
		SupportedProtocolVersions: []string{"2026-07-28", "2025-11-25"},
		PageSize:                  20,
		SetCacheable: func(_ context.Context, _ sdk.Request, cache *sdk.Cacheable) {
			cache.TTLMs = 0
			cache.CacheScope = "private"
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if operations != nil {
		registerContextTools(server, operations)
	}
	if audited != nil {
		server.AddReceivingMiddleware(auditedReceivingMiddleware(operations))
	}
	protocol := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, MaxRequestBodyBytes: MaxRequestBytes,
		PropagateRequestCancellation: true,
		Logger:                       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, ErrConfiguration
	}
	return &Handler{config: c, identities: resolver, protocol: protocol, slots: make(chan struct{}, c.MaxConcurrent), wire: wire, normalWork: make(chan struct{}, c.MaxConcurrent), stopWork: make(chan struct{}, 4), normalFlight: map[identity.Principal]int{}, stopFlight: map[identity.Principal]int{}, inFlight: make(map[identity.Principal]int), now: time.Now, operations: operations, audited: audited}, nil
}

func registerContextTools(server *sdk.Server, operations presentation.Operations) {
	for _, name := range operations.ToolNames() {
		description, _ := operations.Tool(name)
		var annotations sdk.ToolAnnotations
		_ = json.Unmarshal(description.Annotations, &annotations)
		server.AddTool(&sdk.Tool{Name: name, Description: description.Description, Annotations: &annotations, InputSchema: description.InputSchema, OutputSchema: description.OutputSchema}, func(ctx context.Context, request *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			current, ok := ctx.Value(operationIdentityKey{}).(identities.CurrentIdentity)
			delivery, bounded := ctx.Value(operationDeadlineKey{}).(*operationDeadline)
			if !ok || !bounded || request.Params.Name != name || request.Params.RequestState != "" || len(request.Params.InputResponses) != 0 {
				return nil, errors.New("invalid investigation request")
			}
			if attempt, exists := ctx.Value(operationAttemptKey{}).(*operationAttempt); exists {
				if !attempt.claim(attemptDispatched) {
					return nil, errors.New("investigation request unavailable")
				}
				// SDK cancellation for the older protocol is independent. Always use
				// the original authenticated HTTP context for audit and service work.
				ctx = context.WithValue(attempt.owner, operationAttemptKey{}, attempt)
			}
			reply, err := operations.Call(ctx, current, name, request.Params.Arguments)
			if !delivery.retain(reply) {
				return nil, errors.New("investigation response unavailable")
			}
			if err != nil {
				class := "unavailable"
				var stop interface{ FixedStep() string }
				if errors.As(err, &stop) {
					class = stop.FixedStep()
				} else if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
					class = "deadline"
				}
				delivery.fail(name + " " + class)
				if reply.ValidUntil.IsZero() {
					if a, exists := ctx.Value(operationAttemptKey{}).(*operationAttempt); exists {
						a.security.Add(presentation.IngressAuditUnavailable)
					}
				}
				delivery.restrict(reply.ValidUntil)
				return nil, errors.New("investigation request unavailable or invalid")
			}
			if !delivery.restrict(reply.ValidUntil) {
				return nil, errors.New("investigation response authority unavailable")
			}
			b := reply.Body
			var status struct {
				Status string `json:"status"`
			}
			_ = json.Unmarshal(b, &status)
			return &sdk.CallToolResult{StructuredContent: json.RawMessage(b), Content: []sdk.Content{&sdk.TextContent{Text: string(b)}}, IsError: status.Status == "error"}, nil
		})
	}
}

func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
}
func problem(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/problem+json")
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
	}{http.StatusText(status), status})
}
func (h *Handler) challenge(w http.ResponseWriter, status int, code string) {
	value := `Bearer resource_metadata="` + h.config.PublicOrigin + MetadataPath + `"`
	if code != "" {
		value += `, error="` + code + `"`
	}
	if status == http.StatusForbidden {
		value += `, scope="evidence:read"`
	}
	w.Header().Set("WWW-Authenticate", value)
	problem(w, status)
}

type pinnedResolver struct{ handler *Handler }

func (r pinnedResolver) Resolve(ctx context.Context, token string) (identity.Identity, error) {
	return r.handler.resolve(ctx, token)
}

func (h *Handler) resolve(ctx context.Context, token string) (identity.Identity, error) {
	i, err := h.identities.Resolve(ctx, token)
	if err != nil {
		return identity.Identity{}, err
	}
	if ctx.Err() != nil || !i.Valid(h.now()) || i.Principal.Issuer != h.config.Issuer {
		return identity.Identity{}, identity.ErrDenied
	}
	return i, nil
}
func (h *Handler) authFailure(w http.ResponseWriter, err error, reason string) {
	if errors.Is(err, identity.ErrInvalid) || errors.Is(err, identity.ErrDenied) {
		h.challenge(w, 401, "invalid_token")
		return
	}
	h.unavailable(w, reason)
}
func (h *Handler) acquireIdentity(p identity.Principal) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inFlight[p] >= h.config.MaxPerIdentity {
		return false
	}
	h.inFlight[p]++
	return true
}
func (h *Handler) releaseIdentity(p identity.Principal) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.inFlight[p]--
	if h.inFlight[p] == 0 {
		delete(h.inFlight, p)
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	origin, _ := url.Parse(h.config.PublicOrigin)
	if r.TLS == nil || r.Host != origin.Host || r.URL.IsAbs() || r.URL.RawQuery != "" || r.URL.RawPath != "" || len(r.RequestURI) > 4096 || len(r.Header.Values("Origin")) > 1 || r.Header.Get("Origin") != "" && r.Header.Get("Origin") != h.config.PublicOrigin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		h.security.Add(presentation.IngressPreAdmission)
		problem(w, 403)
		return
	}
	if r.URL.Path == MetadataPath {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			problem(w, 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		scopes := []string{"evidence:read"}
		if h.operations != nil {
			if _, ok := h.operations.Tool("request_capture"); ok {
				scopes = append(scopes, "evidence:capture")
			}
			if _, ok := h.operations.Tool("prepare_artifact_download"); ok {
				scopes = append(scopes, "evidence:download")
			}
		}
		_ = json.NewEncoder(w).Encode(struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
			Scopes               []string `json:"scopes_supported"`
			Methods              []string `json:"bearer_methods_supported"`
		}{h.config.Resource(), []string{h.config.Issuer}, scopes, []string{"header"}})
		return
	}
	if r.URL.Path != Path {
		problem(w, 404)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		problem(w, 405)
		return
	}
	if len(r.Header.Values("Authorization")) != 1 || r.Header.Get("Cookie") != "" {
		h.security.Add(presentation.IngressPreAdmission)
		h.challenge(w, 401, "")
		return
	}
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || len(fields[1]) > 16<<10 {
		h.security.Add(presentation.IngressPreAdmission)
		h.challenge(w, 401, "invalid_token")
		return
	}
	// Bound authentication work as well as tool work. Map size cannot exceed
	// this admission bound, and entries leave only when requests have finished.
	admissionHeld := false
	select {
	case h.slots <- struct{}{}:
		admissionHeld = true
		defer func() {
			if admissionHeld {
				<-h.slots
			}
		}()
	default:
		h.security.Add(presentation.IngressOverloaded)
		problem(w, 429)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestLifetime)
	defer cancel()
	current, i, err := identities.NewBearerRequest(ctx, pinnedResolver{h}, fields[1], h.now)
	if err != nil {
		h.security.Add(presentation.IngressPreAdmission)
		h.authFailure(w, err, "identity")
		return
	}
	if h.audited == nil && !h.stopSupported() && !slices.Contains(i.Scopes, "evidence:read") {
		h.challenge(w, 403, "insufficient_scope")
		return
	}
	ctx, stop := context.WithDeadline(ctx, i.ValidUntil)
	defer stop()
	ctx = context.WithValue(ctx, operationIdentityKey{}, current)
	deadline, _ := ctx.Deadline()
	delivery := &operationDeadline{until: deadline}
	ctx = context.WithValue(ctx, operationDeadlineKey{}, delivery)
	r = r.WithContext(ctx)
	control := http.NewResponseController(w)
	if control.SetReadDeadline(deadline) != nil || control.SetWriteDeadline(deadline) != nil {
		h.unavailable(w, "deadline-setup")
		return
	}
	// Header rejection is deferred until bounded routing classification so
	// handshake/list traffic never becomes an audited business invocation.
	invalidHeaders := false
	for _, key := range []string{"Mcp-Session-Id", "Last-Event-Id", "Content-Encoding"} {
		invalidHeaders = invalidHeaders || len(r.Header.Values(key)) != 0
	}
	for _, key := range []string{"Content-Type", "Mcp-Protocol-Version", "Mcp-Method", "Mcp-Name"} {
		invalidHeaders = invalidHeaders || len(r.Header.Values(key)) > 1
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
	defer clear(body)
	if len(body) > MaxRequestBytes {
		h.security.Add(presentation.IngressOversized)
		problem(w, 413)
		return
	}
	if err != nil {
		h.security.Add(presentation.IngressPreAdmission)
		problem(w, 400)
		return
	}
	if invalidHeaders {
		if h.rejectIngress(w, r, current, delivery, "", body, presentation.IngressInvalid) {
			problem(w, 400)
		}
		return
	}
	if !validFrame(body) {
		if h.rejectIngress(w, r, current, delivery, "", body, presentation.IngressInvalid) {
			rpcProblem(w, -32600, "Invalid request")
		}
		return
	}
	if !routingAgrees(r.Header, body) {
		if h.rejectIngress(w, r, current, delivery, "", body, presentation.IngressInvalid) {
			rpcProblem(w, -32600, "Inconsistent routing headers")
		}
		return
	}
	// This endpoint has no subscription, logging, resources, roots, prompts or
	// client callbacks. In particular, never allow subscriptions/listen to turn
	// this finite JSON response into an unbounded SSE stream.
	route, _ := decodeRouting(body)
	if !slices.Contains([]string{"initialize", "notifications/initialized", "server/discover", "ping", "tools/list", "tools/call"}, route.Method) {
		if h.rejectIngress(w, r, current, delivery, "", body, presentation.IngressInvalid) {
			rpcProblem(w, -32601, "Method not available")
		}
		return
	}
	if r.Header.Get("Mcp-Protocol-Version") == "" && route.Method != "initialize" {
		if h.rejectIngress(w, r, current, delivery, route.Name, body, presentation.IngressInvalid) {
			rpcProblem(w, -32600, "Protocol version required")
		}
		return
	}
	if !slices.Contains(i.Scopes, "evidence:read") && !(h.stopSupported() && (route.Method != "tools/call" || route.Name == "cancel_artifact_download")) {
		if route.Method != "tools/call" || h.rejectIngress(w, r, current, delivery, route.Name, body, presentation.IngressDenied) {
			h.challenge(w, 403, "insufficient_scope")
		}
		return
	}
	// Authentication/body parsing remains finite. Long normal provider calls
	// cannot occupy the stop execution slots or its per-principal allowance.
	if route.Method == "tools/call" {
		stopCall := route.Name == "cancel_artifact_download" && h.stopSupported() && h.validStopInput(body)
		slots := h.normalWork
		if stopCall {
			slots = h.stopWork
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			h.security.Add(presentation.IngressOverloaded)
			problem(w, 429)
			return
		}
		if !h.acquireLaneIdentity(i.Principal, stopCall) {
			h.security.Add(presentation.IngressOverloaded)
			problem(w, 429)
			return
		}
		defer h.releaseLaneIdentity(i.Principal, stopCall)
		<-h.slots
		admissionHeld = false
	} else {
		// Protocol discovery still owns its bounded per-principal admission until
		// the SDK call joins. It cannot bypass accounting by avoiding tools/call.
		if !h.acquireIdentity(i.Principal) {
			h.security.Add(presentation.IngressOverloaded)
			problem(w, 429)
			return
		}
		defer h.releaseIdentity(i.Principal)
	}
	var attempt *operationAttempt
	if h.audited != nil && route.Method == "tools/call" {
		attempt = &operationAttempt{input: bytes.Clone(body), owner: ctx, current: current, audited: h.audited, delivery: delivery, security: &h.security}
		ctx = context.WithValue(ctx, operationAttemptKey{}, attempt)
		r = r.WithContext(ctx)
		defer attempt.close()
	}
	// Tool notifications cannot execute an effect without a request/result
	// correlation. Reject before SDK dispatch, including malformed/null IDs.
	if route.Method == "tools/call" {
		if _, ok := invocationID(body); !ok {
			if h.rejectIngress(w, r, current, delivery, route.Name, body, presentation.IngressInvalid) {
				rpcRejected(w, body)
			}
			return
		}
	}
	// The SDK owns revision-specific initialization, metadata and header/body
	// agreement. Do not emulate future protocol fields or retain transport state.
	response := newBoundedResponse()
	defer func() { clear(response.body) }()
	defer delivery.close(ctx)
	r.Body = io.NopCloser(bytes.NewReader(body))
	h.protocol.ServeHTTP(response, r)
	if attempt != nil && attempt.claim(attemptRejected) {
		// SDK request/header/parameter decoding can reject before middleware.
		// Claim once before auditing; a delayed SDK callback cannot dispatch.
		if !attempt.reject(route.Name, body, presentation.IngressInvalid) {
			h.unavailable(w, "audit-reject")
			return
		}
		// Never forward decoder diagnostics: they may quote raw arguments.
		clear(response.body)
		response = newBoundedResponse()
		rpcRejected(response, body)
	}
	if response.overflow {
		h.unavailable(w, "response-overflow")
		return
	}
	// Even discovery/list output cannot survive identity/policy revocation while
	// SDK work blocked. A refreshed observation never extends the original lease.
	// Workload/recovery authorization may expire earlier than identity, including
	// while this final identity check blocks; preserve both independent bounds.
	finalIdentity, err := current.ResolveIdentity(ctx)
	if err != nil {
		h.authFailure(w, err, "final-identity")
		return
	}
	if failure := delivery.failed(); failure != "" {
		// A failed call leaves no delivery deadline; report it as what it is.
		h.unavailable(w, "operation-failed "+failure)
		return
	}
	if !delivery.restrict(finalIdentity.ValidUntil) {
		h.unavailable(w, "final-identity-expired")
		return
	}
	deadline, valid := delivery.current(h.now())
	if !valid || ctx.Err() != nil {
		h.unavailable(w, "deadline-passed")
		return
	}
	// Copy only protocol headers; the SDK cannot relax our cache/privacy headers
	// or write a session identifier through a compatibility environment flag.
	if kind := response.header.Get("Content-Type"); kind != "" {
		w.Header().Set("Content-Type", kind)
	}
	if allow := response.header.Get("Allow"); allow != "" {
		w.Header().Set("Allow", allow)
	}
	if response.status == http.StatusServiceUnavailable && h.Report != nil {
		h.Report("protocol")
	}
	writeCtx, finishWrite := delivery.responseContext(ctx)
	defer finishWrite()
	if sent, err := presentation.WriteOperationResponse(writeCtx, w, response.status, response.body, deadline, delivery.check); err != nil && !sent {
		h.unavailable(w, "final-disclosure")
	}
}

// SDK v1.8 validates standard routing headers only for the new protocol.
// Older callers may omit them, but a supplied hint must never disagree with
// the JSON body. No routing headers select authority or service handlers.
type routing struct{ Method, Name, URI string }

func decodeRouting(body []byte) (routing, bool) {
	var out routing
	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) != nil {
		return out, false
	}
	// The JSON-RPC envelope is closed. Case aliases must not be interpreted
	// differently by our guard, the SDK parser or an HTTP routing intermediary.
	for key := range root {
		if !slices.Contains([]string{"jsonrpc", "id", "method", "params"}, key) {
			return out, false
		}
	}
	if json.Unmarshal(root["method"], &out.Method) != nil || len(out.Method) > 128 {
		return out, false
	}
	if raw, exists := root["params"]; exists {
		var params map[string]json.RawMessage
		if json.Unmarshal(raw, &params) != nil {
			return out, false
		}
		for key := range params {
			for _, reserved := range []string{"name", "uri", "_meta", "arguments"} {
				if strings.EqualFold(key, reserved) && key != reserved {
					return out, false
				}
			}
		}
		if raw, exists := params["name"]; exists && json.Unmarshal(raw, &out.Name) != nil {
			return out, false
		}
		if raw, exists := params["uri"]; exists && json.Unmarshal(raw, &out.URI) != nil {
			return out, false
		}
	}
	return out, true
}

func routingAgrees(header http.Header, body []byte) bool {
	route, ok := decodeRouting(body)
	if !ok {
		return false
	}
	if hint := header.Get("Mcp-Method"); hint != "" && hint != route.Method {
		return false
	}
	name := ""
	switch route.Method {
	case "tools/call", "prompts/get":
		name = route.Name
	case "resources/read":
		name = route.URI
	}
	if hint := header.Get("Mcp-Name"); hint != "" && hint != name {
		return false
	}
	for key := range header {
		if strings.HasPrefix(http.CanonicalHeaderKey(key), "Mcp-Param-") {
			return false
		}
	}
	return true
}

func validFrame(body []byte) bool {
	if len(body) == 0 || !jsontext.Value(body).IsValid() {
		return false
	}
	d := jsontext.NewDecoder(bytes.NewReader(body))
	first, err := d.ReadToken()
	if err != nil || first.Kind() != '{' {
		return false
	}
	for {
		_, err = d.ReadToken()
		if err == io.EOF {
			return true
		}
		if err != nil || d.StackDepth() > maxNesting {
			return false
		}
	}
}
func rpcProblem(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(struct {
		Version string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{Version: "2.0", Error: struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{code, message}})
}

type boundedResponse struct {
	header   http.Header
	body     []byte
	status   int
	overflow bool
}

func newBoundedResponse() *boundedResponse {
	return &boundedResponse{header: make(http.Header), status: http.StatusOK}
}
func (r *boundedResponse) Header() http.Header    { return r.header }
func (r *boundedResponse) WriteHeader(status int) { r.status = status }
func (r *boundedResponse) Write(p []byte) (int, error) {
	if r.overflow || len(p) > MaxResponseBytes-len(r.body) {
		r.overflow = true
		return 0, errors.New("MCP response exceeds limit")
	}
	r.body = append(r.body, p...)
	return len(p), nil
}

// The transport is JSON-only. Flush cannot release buffered output ahead of
// the final authority check; it merely meets the SDK ResponseWriter contract.
func (r *boundedResponse) Flush() {}

func (h *Handler) stopSupported() bool {
	if h.operations == nil {
		return false
	}
	_, ok := h.operations.Tool("cancel_artifact_download")
	return ok
}
func (h *Handler) acquireLaneIdentity(p identity.Principal, stop bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	active := h.normalFlight
	if stop {
		active = h.stopFlight
	}
	if active[p] >= h.config.MaxPerIdentity {
		return false
	}
	active[p]++
	return true
}
func (h *Handler) releaseLaneIdentity(p identity.Principal, stop bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	active := h.normalFlight
	if stop {
		active = h.stopFlight
	}
	active[p]--
	if active[p] == 0 {
		delete(active, p)
	}
}

func (h *Handler) validStopInput(body []byte) bool {
	if h.wire == nil {
		return false
	}
	var call struct {
		Params struct {
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	return json.Unmarshal(body, &call) == nil && h.wire.ValidateInput("cancel_artifact_download", call.Params.Arguments) == nil
}
