package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

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
