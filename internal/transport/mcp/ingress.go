package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/transport/presentation"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type operationAttemptKey struct{}

const (
	attemptUnclaimed uint32 = iota
	attemptDispatched
	attemptRejected
	attemptClosed
)

// The owner is the original authenticated HTTP request, including its original
// cancellation/deadline. The SDK's older-revision context cannot detach it.
// Exactly one callback or proven rejection owns the operation audit.
type operationAttempt struct {
	inputMu  sync.Mutex
	input    []byte
	state    atomic.Uint32
	owner    context.Context
	current  identities.CurrentIdentity
	audited  *presentation.AuditedOperations
	delivery *operationDeadline
	security *presentation.IngressCounters
}

func (a *operationAttempt) claim(kind uint32) bool {
	return a.owner.Err() == nil && a.state.CompareAndSwap(attemptUnclaimed, kind)
}
func (a *operationAttempt) close() {
	a.state.Store(attemptClosed)
	a.inputMu.Lock()
	clear(a.input)
	a.input = nil
	a.inputMu.Unlock()
}
func (a *operationAttempt) rejectionInput() []byte {
	a.inputMu.Lock()
	defer a.inputMu.Unlock()
	return bytes.Clone(a.input)
}
func (a *operationAttempt) reject(name string, raw []byte, kind presentation.IngressRejectionKind) bool {
	// The full bounded input still includes an overlong/invalid name. Never pass
	// an attacker-controlled unbounded name as a journal field or error string.
	if len(name) > 128 || !utf8.ValidString(name) {
		name = ""
	}
	until, err := a.audited.RejectBeforeDispatch(a.owner, a.current, presentation.IngressRejection{RequestedOperation: name, Input: raw, Kind: kind})
	if err != nil || !a.delivery.restrict(until) {
		a.delivery.restrict(until)
		a.security.Add(presentation.IngressAuditUnavailable)
		return false
	}
	return true
}
func auditedReceivingMiddleware(ops presentation.Operations) sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, request sdk.Request) (sdk.Result, error) {
			if method != "tools/call" {
				return next(ctx, method, request)
			}
			a, ok := ctx.Value(operationAttemptKey{}).(*operationAttempt)
			req, typed := request.(*sdk.CallToolRequest)
			if !ok || !typed || req.Params == nil {
				return nil, &jsonrpc.Error{Code: -32602, Message: "Invalid investigation request"}
			}
			_, known := ops.Tool(req.Params.Name)
			if known && req.Params.RequestState == "" && len(req.Params.InputResponses) == 0 {
				return next(ctx, method, request)
			}
			if !a.claim(attemptRejected) {
				return nil, &jsonrpc.Error{Code: -32603, Message: "Investigation unavailable"}
			}
			raw := a.rejectionInput()
			defer clear(raw)
			if len(raw) == 0 || !a.reject(req.Params.Name, raw, presentation.IngressInvalid) {
				return nil, &jsonrpc.Error{Code: -32603, Message: "Investigation unavailable"}
			}
			return nil, &jsonrpc.Error{Code: -32602, Message: "Invalid investigation request"}
		}
	}
}

// rejectIngress only covers an authenticated bounded invocation. Missing/invalid
// authentication, oversized input and exhausted admission use fixed counters.
// Legacy component constructors intentionally have no durable rejection claim.
func (h *Handler) rejectIngress(w http.ResponseWriter, r *http.Request, current identities.CurrentIdentity, delivery *operationDeadline, name string, raw []byte, kind presentation.IngressRejectionKind) bool {
	if h.audited == nil {
		return true
	}
	if route, ok := decodeRouting(raw); ok {
		if slices.Contains([]string{"initialize", "notifications/initialized", "server/discover", "ping", "tools/list"}, route.Method) {
			h.security.Add(presentation.IngressPreAdmission)
			return true
		}
		if name == "" && route.Method == "tools/call" {
			name = route.Name
		}
	}
	a := &operationAttempt{owner: r.Context(), current: current, audited: h.audited, delivery: delivery, security: &h.security}
	if !a.claim(attemptRejected) || !a.reject(name, raw, kind) {
		problem(w, 503)
		return false
	}
	final, err := current.ResolveIdentity(r.Context())
	if err != nil || r.Context().Err() != nil || !delivery.restrict(final.ValidUntil) {
		problem(w, 503)
		return false
	}
	deadline, valid := delivery.current(h.now())
	if !valid || http.NewResponseController(w).SetWriteDeadline(deadline) != nil {
		problem(w, 503)
		return false
	}
	return true
}

// Keep a syntactically scalar caller ID for JSON-RPC correlation while replacing
// every SDK diagnostic with fixed text. No error-text parsing or raw parameters.
func rpcRejected(w http.ResponseWriter, body []byte) {
	id, ok := invocationID(body)
	if !ok {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(struct {
		Version string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   *jsonrpc.Error  `json:"error"`
	}{"2.0", id, &jsonrpc.Error{Code: -32602, Message: "Invalid investigation request"}})
}

func invocationID(body []byte) (json.RawMessage, bool) {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(body, &envelope) != nil {
		return nil, false
	}
	raw := envelope["id"]
	var scalar any
	if len(raw) == 0 || json.Unmarshal(raw, &scalar) != nil {
		return nil, false
	}
	switch scalar.(type) {
	case string, float64:
		return raw, true
	}
	return nil, false
}
