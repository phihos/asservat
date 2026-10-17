package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"k8s.io/client-go/rest"
)

type projectionBoundaryTransport struct {
	base   http.RoundTripper
	before func(*http.Request) error
	after  func(*http.Request, *http.Response) error
}

func (h projectionBoundaryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if h.before != nil {
		if err := h.before(r); err != nil {
			return nil, err
		}
	}
	out, err := h.base.RoundTrip(r)
	if err == nil && h.after != nil {
		if err = h.after(r, out); err != nil {
			out.Body.Close()
			return nil, err
		}
	}
	return out, err
}
func hookProjection(t *testing.T, f *publicRoleRootFixture, before func(*http.Request) error, after func(*http.Request, *http.Response) error) *atomic.Int32 {
	t.Helper()
	denials := &atomic.Int32{}
	for _, c := range []*PermissionClient{f.root.client, f.root.protection.probe} {
		api := c.api.(*rest.RESTClient)
		original := api.Client.Transport
		api.Client.Transport = projectionBoundaryTransport{base: original, before: func(r *http.Request) error {
			if r.URL.Query().Get("dryRun") == "All" {
				denials.Add(1)
			}
			if before != nil {
				return before(r)
			}
			return nil
		}, after: after}
		t.Cleanup(func() { api.Client.Transport = original })
	}
	return denials
}
func projectionState(t *testing.T, f *publicRoleRootFixture) contracts.PublicRuntimeRoleState {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	v, e := contracts.DecodePublicRuntimeRoleState(bytes.NewReader(f.object.Data["state.json"]))
	if e != nil {
		t.Fatal("original fixture state invalid")
	}
	return v
}
func projectionRootPUT(f *publicRoleRootFixture, r *http.Request) bool {
	return r.Method == http.MethodPut && r.URL.Path == f.root.path()+"/"+f.root.name()
}
func replaceProjectionJSON(r *http.Response, change func(map[string]any)) error {
	b, e := io.ReadAll(r.Body)
	r.Body.Close()
	if e != nil {
		return e
	}
	defer clear(b)
	var v map[string]any
	if e = json.Unmarshal(b, &v); e != nil {
		return e
	}
	change(v)
	b, e = json.Marshal(v)
	if e != nil {
		return e
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.ContentLength = int64(len(b))
	return nil
}

type projectionConfigurationChange struct {
	f       *publicRoleRootFixture
	changed *atomic.Bool
	shorten bool
}

func (r projectionConfigurationChange) ReadOwnerConfiguration(ctx context.Context) (fleet.OwnerConfigurationObservation, error) {
	v, e := r.f.ReadOwnerConfiguration(ctx)
	if e == nil && r.changed.Load() {
		if r.shorten {
			v.FreshUntil = time.Now().Add(200 * time.Millisecond)
		} else {
			v.Configuration.Revision.Generation++
		}
	}
	return v, e
}

func TestPublicProjectionCurrentBoundaries(t *testing.T) {
	for _, boundary := range []string{"after-root-read", "after-claim", "before-receipt", "after-receipt"} {
		t.Run(boundary, func(t *testing.T) {
			f, v := completedPublicRoleFixture(t)
			var puts, gets atomic.Int32
			denials := hookProjection(t, f, nil, func(r *http.Request, out *http.Response) error {
				if r.Method == http.MethodGet && r.URL.Path == f.root.path()+"/"+f.root.name() && gets.Add(1) == 1 && boundary == "after-root-read" {
					f.badAdmin.Store(true)
				}
				if projectionRootPUT(f, r) {
					n := puts.Add(1)
					if n == 1 && boundary == "after-claim" || n == 2 && boundary == "after-receipt" {
						f.badAdmin.Store(true)
					}
				}
				if r.URL.Path == f.root.path()+"/"+f.root.projectionName() && boundary == "before-receipt" {
					f.badAdmin.Store(true)
				}
				return nil
			})
			_, e := f.root.PublishPublicRuntimeProjection(t.Context(), v)
			if !errors.Is(e, cfg.ErrDenied) {
				t.Fatalf("current admin denial missing: %v", e)
			}
			wantPuts, wantCreates := int32(0), int32(0)
			if boundary != "after-root-read" {
				wantPuts = 1
			}
			if boundary == "before-receipt" || boundary == "after-receipt" {
				wantCreates = 1
			}
			if boundary == "after-receipt" {
				wantPuts = 2
			}
			if puts.Load() != wantPuts || f.projectionWrites.Load() != wantCreates || denials.Load() != 1 {
				t.Fatalf("crossed denied boundary: puts=%d creates=%d proofs=%d", puts.Load(), f.projectionWrites.Load(), denials.Load())
			}
			state := projectionState(t, f)
			if (state.Projection != nil && state.Projection.SecretUID != "") != (boundary == "after-receipt") {
				t.Fatal("uncertain committed receipt lost or fabricated")
			}
		})
	}
}
func TestPublicProjectionChangedPinsCannotReuseProof(t *testing.T) {
	for _, field := range []string{"policy-version", "binding", "namespace", "worker-journal", "worker-deployment", "account", "lease", "source"} {
		t.Run(field, func(t *testing.T) {
			f, v := completedPublicRoleFixture(t)
			var changed atomic.Bool
			f.root.configurations = projectionConfigurationChange{f: f, changed: &changed}
			denials := hookProjection(t, f, nil, func(r *http.Request, out *http.Response) error {
				if projectionRootPUT(f, r) {
					changed.Store(true)
				}
				if !changed.Load() || r.Method != http.MethodGet {
					return nil
				}
				path := r.URL.Path
				match := field == "policy-version" && strings.Contains(path, "/validatingadmissionpolicies/") || field == "binding" && strings.Contains(path, "/validatingadmissionpolicybindings/") || field == "namespace" && path == "/api/v1/namespaces/owners" || field == "worker-journal" && strings.HasSuffix(path, "/"+f.input.Worker.Resources.Name) || field == "worker-deployment" && strings.HasSuffix(path, "/deployments/"+f.input.Worker.Deployment.Reference.Name) || field == "account" && strings.Contains(path, "/serviceaccounts/") || field == "lease" && strings.Contains(path, "/leases/")
				if !match {
					return nil
				}
				return replaceProjectionJSON(out, func(v map[string]any) {
					m := v["metadata"].(map[string]any)
					if field == "policy-version" {
						m["resourceVersion"] = "changed"
					} else {
						m["uid"] = ownerID(9000)
					}
				})
			})
			_, e := f.root.PublishPublicRuntimeProjection(t.Context(), v)
			if !errors.Is(e, cfg.ErrChanged) || f.projectionWrites.Load() != 0 || denials.Load() != 1 {
				t.Fatalf("changed original pin accepted or proof renewed: changed=%t creates=%d proofs=%d", errors.Is(e, cfg.ErrChanged), f.projectionWrites.Load(), denials.Load())
			}
		})
	}
}

func TestPublicProjectionBlockedReadRetainsOriginalDeadline(t *testing.T) {
	for _, mode := range []string{"verified", "shorter-source", "cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			f, v := completedPublicRoleFixture(t)
			var claimed atomic.Bool
			var blocked atomic.Bool
			if mode == "shorter-source" {
				f.root.configurations = projectionConfigurationChange{f: f, changed: &claimed, shorten: true}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			reached := make(chan struct{})
			release := make(chan struct{})
			denials := hookProjection(t, f, func(r *http.Request) error {
				if claimed.Load() && (mode == "shorter-source" && r.URL.Path == "/api/v1/namespaces/owners" || mode != "shorter-source" && strings.HasSuffix(r.URL.Path, "/"+f.input.Worker.Resources.Name)) {
					blocked.Store(true)
					close(reached)
					if mode == "cancel" {
						cancel()
					}
					<-r.Context().Done()
					if mode == "close" {
						<-release
					}
					return r.Context().Err()
				}
				return nil
			}, func(r *http.Request, _ *http.Response) error {
				if projectionRootPUT(f, r) {
					claimed.Store(true)
				}
				return nil
			})
			result := make(chan error, 1)
			go func() { _, e := f.root.PublishPublicRuntimeProjection(ctx, v); result <- e }()
			if mode == "close" {
				select {
				case <-reached:
				case <-time.After(5 * time.Second):
					t.Fatal("owned read was not reached")
				}
				closed := make(chan struct{})
				go func() { f.root.Close(); close(closed) }()
				select {
				case <-closed:
					t.Fatal("Close returned before owned read joined")
				case <-time.After(30 * time.Millisecond):
				}
				close(release)
				<-closed
			}
			e := <-result
			if !blocked.Load() || !errors.Is(e, cfg.ErrUnavailable) || errors.Is(e, cfg.ErrChanged) || f.projectionWrites.Load() != 0 || denials.Load() != 1 {
				t.Fatalf("blocked read changed authority: blocked=%t unavailable=%t creates=%d proofs=%d", blocked.Load(), errors.Is(e, cfg.ErrUnavailable), f.projectionWrites.Load(), denials.Load())
			}
			if mode == "verified" && time.Now().Before(v.ValidUntil) {
				t.Fatal("did not test original expiry")
			}
		})
	}
}
func TestPublicProjectionUnknownReceiptRemainsExact(t *testing.T) {
	f, v := completedPublicRoleFixture(t)
	var puts atomic.Int32
	denials := hookProjection(t, f, nil, func(r *http.Request, _ *http.Response) error {
		if projectionRootPUT(f, r) && puts.Add(1) == 2 {
			return errors.New("synthetic lost receipt response")
		}
		return nil
	})
	if _, e := f.root.PublishPublicRuntimeProjection(t.Context(), v); !errors.Is(e, cfg.ErrUnavailable) {
		t.Fatal("unknown receipt reported success", e)
	}
	first := projectionState(t, f)
	if first.Projection == nil || first.Projection.SecretUID == "" || f.projectionWrites.Load() != 1 || denials.Load() != 1 {
		t.Fatal("original committed receipt missing")
	}
	fresh, e := f.root.ReadPublicRuntimeRoles(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	before := denials.Load()
	ref, e := f.root.PublishPublicRuntimeProjection(t.Context(), fresh)
	last := projectionState(t, f)
	if e != nil || ref.UID != first.Projection.SecretUID || *last.Projection != *first.Projection || f.projectionWrites.Load() != 1 || puts.Load() != 2 || denials.Load() != before+1 {
		t.Fatal("reopen replaced receipt or reused a cross-call proof", e)
	}
}

func TestPublicProjectionFailedOperationCannotReacquire(t *testing.T) {
	f, v := completedPublicRoleFixture(t)
	ctx, end, e := f.root.enter(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	defer end()
	op := newPublicProjectionOperation(ctx, f.root, v)
	defer op.close()
	var calls atomic.Int32
	denials := hookProjection(t, f, func(*http.Request) error { calls.Add(1); return nil }, nil)
	if e = op.current(); e != nil {
		t.Fatal(e)
	}
	originalStart, originalEnd := op.started, op.until
	f.badAdmin.Store(true)
	if e = op.current(); !errors.Is(e, cfg.ErrDenied) {
		t.Fatal("revoked actor not observed", e)
	}
	n := calls.Load()
	f.badAdmin.Store(false)
	if e = op.current(); !errors.Is(e, cfg.ErrDenied) || calls.Load() != n || denials.Load() != 1 || !op.started.Equal(originalStart) || !op.until.Equal(originalEnd) {
		t.Fatal("failed operation reacquired or renewed proof")
	}
}
