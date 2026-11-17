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

func TestAuditedMCPAuditFailureReportsBeforeFinalIdentity(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		for _, mode := range []string{"named", "unnamed"} {
			t.Run(version+"/"+mode, func(t *testing.T) {
				h, server, capture, rows, _ := auditedMCPFixture(t)
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
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				original, _ := ctx.Deadline()
				rows.err = auditObjectDiagnostic{}
				want := "operation-failed request_capture audit/credentials-configuration/transaction/begin-deadline"
				if mode == "unnamed" {
					rows.err = errors.New("private provider token and address")
					want = "operation-failed request_capture audit"
				}
				w := &auditFailureResponse{ResponseRecorder: httptest.NewRecorder(), beforeWrite: func() {
					mu.Lock()
					defer mu.Unlock()
					if !slices.Equal(reports, []string{want}) {
						t.Errorf("original audit failure missing before response: %q", reports)
					}
				}}
				req := rpcRequest(t, server, version, "tools/call", map[string]any{"name": "request_capture", "arguments": mcpCaptureRequest()}).WithContext(ctx)
				req.TLS = &tls.ConnectionState{}
				req.RequestURI = req.URL.RequestURI()
				req.URL.Scheme, req.URL.Host = "", ""
				h.ServeHTTP(w, req)

				mu.Lock()
				defer mu.Unlock()
				if !slices.Equal(reports, []string{want}) {
					t.Fatalf("diagnostic missing or duplicated: %q", reports)
				}
				if len(order) < 2 || order[len(order)-2] != "report" || order[len(order)-1] != "identity" || w.Code != http.StatusServiceUnavailable {
					t.Fatalf("final identity/response changed: order=%q status=%d", order, w.Code)
				}
				if !w.read.Equal(original) || !w.write.Equal(original) {
					t.Fatal("failure reporting changed original socket bounds")
				}
				if rows.count() != 1 || capture.calls.Load() != 1 {
					t.Fatal("failure reporting repeated audit or service work")
				}
				if strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "credentials") {
					t.Fatal("private diagnostic entered public response")
				}
			})
		}
	}
}
