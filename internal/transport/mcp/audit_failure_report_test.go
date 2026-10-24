package mcp

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

// The object boundary supplies only its existing closed diagnostic. Its raw
// provider error deliberately contains text that must never reach a report.
type auditObjectDiagnostic struct{}

func (auditObjectDiagnostic) Error() string { return "private provider token and address" }
func (auditObjectDiagnostic) FixedStep() string {
	return "credentials-configuration/transaction/begin-deadline"
}

type auditFailureResponse struct {
	*httptest.ResponseRecorder
	read, write time.Time
	beforeWrite func()
}

func (w *auditFailureResponse) SetReadDeadline(until time.Time) error {
	w.read = until
	return nil
}
func (w *auditFailureResponse) SetWriteDeadline(until time.Time) error {
	w.write = until
	return nil
}
func (w *auditFailureResponse) WriteHeader(status int) {
	w.beforeWrite()
	w.ResponseRecorder.WriteHeader(status)
}

func TestAuditedMCPBeginFailureReportsBeforeFinalIdentity(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		for _, mode := range []string{"original-deadline", "live", "unnamed"} {
			t.Run(version+"/"+mode, func(t *testing.T) {
				h, server, capture, normal, resolution, _ := auditedMCPFixture(t)
				var mu sync.Mutex
				var reports, order []string
				h.Report = func(reason string) {
					mu.Lock()
					defer mu.Unlock()
					reports = append(reports, reason)
					order = append(order, "report")
				}
				h.identities = resolverFunc(func(context.Context, string) (identity.Identity, error) {
					mu.Lock()
					order = append(order, "identity")
					mu.Unlock()
					i := testIdentity()
					i.Scopes = append(i.Scopes, "evidence:capture")
					return i, nil
				})
				bound := time.Second
				if mode == "original-deadline" {
					bound = 75 * time.Millisecond
				}
				ctx, cancel := context.WithTimeout(t.Context(), bound)
				defer cancel()
				original, _ := ctx.Deadline()
				normal.onCreate = func(call context.Context) error {
					until, ok := call.Deadline()
					if !ok || until.After(original) || original.Sub(until) >= time.Microsecond {
						t.Error("audit replaced the original request deadline")
					}
					if mode == "original-deadline" {
						<-call.Done()
						if call.Err() != context.DeadlineExceeded {
							t.Error("audit did not reach the original deadline")
						}
						// Audit SQL rounds its bound down to microseconds.
						// Join the original HTTP cancellation as well so the
						// test does not depend on timer scheduling within 1 µs.
						<-ctx.Done()
					}
					if mode == "unnamed" {
						return errors.New("private provider token and address")
					}
					return auditObjectDiagnostic{}
				}
				want := "operation-failed request_capture audit-begin/object"
				if mode != "unnamed" {
					want += "/credentials-configuration/transaction/begin-deadline"
				}
				w := &auditFailureResponse{ResponseRecorder: httptest.NewRecorder(), beforeWrite: func() {
					mu.Lock()
					defer mu.Unlock()
					if !slices.Equal(reports, []string{want}) {
						t.Errorf("original audit failure missing before response: %q", reports)
					}
				}}
				req := rpcRequest(t, server, version, "tools/call", map[string]any{
					"name": "request_capture", "arguments": map[string]any{
						"preview_id": "00000000-0000-4000-8000-000000000020", "idempotency_key": "same-key",
					},
				}).WithContext(ctx)
				req.TLS = &tls.ConnectionState{}
				req.RequestURI = req.URL.RequestURI()
				req.URL.Scheme, req.URL.Host = "", ""
				h.ServeHTTP(w, req)

				mu.Lock()
				defer mu.Unlock()
				if !slices.Equal(reports, []string{want}) {
					t.Fatalf("diagnostic missing or duplicated: %q", reports)
				}
				// Expired CurrentIdentity refuses locally before calling its
				// resolver; a live request still performs the same final read.
				wantOrder := []string{"identity", "identity", "report"}
				status := http.StatusUnauthorized
				if mode != "original-deadline" {
					wantOrder = append(wantOrder, "identity")
					status = http.StatusServiceUnavailable
				}
				if !slices.Equal(order, wantOrder) || w.Code != status {
					t.Fatalf("final identity/response changed: order=%q status=%d", order, w.Code)
				}
				if !w.read.Equal(original) || !w.write.Equal(original) {
					t.Fatal("failure reporting changed original socket bounds")
				}
				n, o := normal.count()
				r, ro := resolution.count()
				if n != 1 || o != 0 || r != 0 || ro != 0 || normal.claims.Load() != 1 || normal.creates.Load() != 1 || capture.calls.Load() != 0 || capture.continuations.Load() != 0 {
					t.Fatal("failure reporting repeated audit or dispatched service work")
				}
				if strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "credentials") {
					t.Fatal("private diagnostic entered public response")
				}
			})
		}
	}
}
