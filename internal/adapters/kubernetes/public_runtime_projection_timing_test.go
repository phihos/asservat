package kubernetes

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/client-go/rest"
)

// Diagnostic only: actual production limiter and original proof interval are
// unchanged. The transport records closed operation classes/timing only; no
// URL, token, request/response body or private role state is printed.
type projectionTimingTransport struct {
	base    http.RoundTripper
	observe func(*http.Request, time.Duration, int, bool)
}

func (r projectionTimingTransport) RoundTrip(in *http.Request) (*http.Response, error) {
	start := time.Now()
	out, err := r.base.RoundTrip(in)
	status := 0
	if out != nil {
		status = out.StatusCode
	}
	r.observe(in, time.Since(start), status, err != nil)
	return out, err
}

func TestPublicRuntimeProjectionTimingDiagnostic(t *testing.T) {
	f, snapshot := completedPublicRoleFixture(t)
	start := time.Now()
	remaining := time.Until(snapshot.ValidUntil)
	type event struct {
		Class                        string
		ElapsedMS, IOUS, RemainingMS int64
		Status                       int
		Failed, Cancelled            bool
	}
	var mu sync.Mutex
	var events []event
	class := func(r *http.Request) string {
		path := r.URL.Path
		switch {
		case path == f.root.path()+"/"+f.root.name():
			return "role-journal-" + r.Method
		case path == f.root.path()+"/"+f.root.projectionName():
			return "projection-lookup"
		case path == f.root.path() && r.Method == http.MethodPost:
			return "projection-create"
		case strings.Contains(path, "/validatingadmissionpolicybindings/"):
			return "binding"
		case strings.Contains(path, "/validatingadmissionpolicies/"):
			return "policy"
		case strings.HasSuffix(path, "/selfsubjectreviews"):
			return "actor"
		case strings.HasSuffix(path, "/selfsubjectaccessreviews"):
			return "access-review"
		case r.URL.Query().Get("dryRun") != "":
			return "denial-probe"
		case strings.Contains(path, "/deployments/"):
			return "deployment"
		case strings.Contains(path, "/serviceaccounts/"):
			return "account"
		case strings.Contains(path, "/leases/"):
			return "lease"
		case strings.Contains(path, "/secrets/"):
			return "worker-journal"
		default:
			return "namespace-or-other"
		}
	}
	for _, client := range []*PermissionClient{f.root.client, f.root.protection.probe} {
		api, ok := client.api.(*rest.RESTClient)
		if !ok || api.Client == nil || api.Client.Transport == nil {
			t.Fatal("actual bounded transport unavailable")
		}
		original := api.Client.Transport
		api.Client.Transport = projectionTimingTransport{base: original, observe: func(r *http.Request, elapsed time.Duration, status int, failed bool) {
			n := time.Now()
			mu.Lock()
			defer mu.Unlock()
			if len(events) >= 256 {
				t.Error("bounded diagnostic request inventory exceeded")
				return
			}
			events = append(events, event{Class: class(r), ElapsedMS: n.Sub(start).Milliseconds(), IOUS: elapsed.Microseconds(), RemainingMS: snapshot.ValidUntil.Sub(n).Milliseconds(), Status: status, Failed: failed, Cancelled: r.Context().Err() != nil})
		}}
		t.Cleanup(func() { api.Client.Transport = original })
	}
	ref, err := f.root.PublishPublicRuntimeProjection(t.Context(), snapshot)
	f.mu.Lock()
	state, decode := contracts.DecodePublicRuntimeRoleState(bytes.NewReader(f.object.Data["state.json"]))
	projectionExists := f.projection != nil
	f.mu.Unlock()
	t.Logf("projection diagnostic original_remaining_ms=%d duration_ms=%d original_expired=%t changed=%t unavailable=%t claim=%t receipt=%t physical_projection=%t creates=%d root_valid=%t", remaining.Milliseconds(), time.Since(start).Milliseconds(), !time.Now().Before(snapshot.ValidUntil), errors.Is(err, cfg.ErrChanged), errors.Is(err, cfg.ErrUnavailable), state.Projection != nil, state.Projection != nil && state.Projection.SecretUID != "", projectionExists, f.projectionWrites.Load(), decode == nil && runtimeRoleStateValid(f.input, state, time.Now()))
	mu.Lock()
	for _, e := range events {
		t.Logf("projection request class=%s elapsed_ms=%d io_us=%d original_remaining_ms=%d status=%d failed=%t cancelled=%t", e.Class, e.ElapsedMS, e.IOUS, e.RemainingMS, e.Status, e.Failed, e.Cancelled)
	}
	mu.Unlock()
	if err != nil || ref.UID == "" || f.projectionWrites.Load() != 1 {
		t.Fatal("exact projection readback unavailable")
	}
}
