package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Counters retain only fixed resource categories, failure totals and monotonic
// elapsed time. No URL, header, body, principal or error text is retained.
// RoundTrip time ends at response headers; it is not body or server lock time.
type ownerObservationCostCount struct {
	Requests          [2][10]int64 `json:"requests"`
	HTTPFailures      int64        `json:"httpFailures"`
	TransportFailures int64        `json:"transportFailures"`
	RoundTripNanos    int64        `json:"roundTripNanos"`
}
type ownerObservationCostCounter struct {
	mu    sync.Mutex
	armed bool
	value ownerObservationCostCount
}

func (c *ownerObservationCostCounter) arm() {
	c.mu.Lock()
	c.armed = true
	c.value = ownerObservationCostCount{}
	c.mu.Unlock()
}
func (c *ownerObservationCostCounter) snapshot() ownerObservationCostCount {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value
}
func (c *ownerObservationCostCounter) wrap(probe bool) func(http.RoundTripper) http.RoundTripper {
	return func(next http.RoundTripper) http.RoundTripper {
		return ownerProbeRoundTripper(func(r *http.Request) (*http.Response, error) {
			start := time.Now()
			label := ownerObservationCostLabel(r)
			source := 0
			if probe {
				source = 1
			}
			c.mu.Lock()
			armed := c.armed
			if armed {
				c.value.Requests[source][label]++
			}
			c.mu.Unlock()
			out, err := next.RoundTrip(r)
			if armed {
				c.mu.Lock()
				c.value.RoundTripNanos += time.Since(start).Nanoseconds()
				if err != nil {
					c.value.TransportFailures++
				}
				if out != nil && out.StatusCode >= 400 {
					c.value.HTTPFailures++
				}
				c.mu.Unlock()
			}
			return out, err
		})
	}
}
func ownerObservationCostLabel(r *http.Request) int {
	if r == nil || r.URL == nil {
		return 9
	}
	p := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if r.Method == http.MethodGet {
		if len(p) == 4 && p[0] == "api" && p[1] == "v1" && p[2] == "namespaces" {
			return 0
		}
		if len(p) == 5 && p[0] == "apis" && p[1] == "admissionregistration.k8s.io" && p[2] == "v1" {
			if p[3] == "validatingadmissionpolicies" {
				return 1
			}
			if p[3] == "validatingadmissionpolicybindings" {
				return 2
			}
		}
		if len(p) == 6 && p[0] == "api" && p[1] == "v1" && p[2] == "namespaces" {
			if p[4] == "serviceaccounts" {
				return 3
			}
			if p[4] == "pods" {
				return 4
			}
			if p[4] == "services" {
				return 5
			}
		}
		if len(p) == 7 && p[0] == "apis" && p[1] == "apps" && p[2] == "v1" && p[3] == "namespaces" {
			if p[5] == "deployments" {
				return 6
			}
			if p[5] == "replicasets" {
				return 7
			}
		}
		if len(p) == 6 && p[0] == "apis" && p[1] == "discovery.k8s.io" && p[2] == "v1" && p[3] == "namespaces" && p[5] == "endpointslices" {
			return 8
		}
	}
	// All probe HTTP operations share one closed category; no dynamic path is saved.
	if r.Method == http.MethodPost && ((r.URL.Path == "/apis/authentication.k8s.io/v1/selfsubjectreviews") || (r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews")) {
		return 8
	}
	if r.Method == http.MethodPut && len(p) == 7 && p[0] == "apis" && p[1] == "apps" && p[2] == "v1" && p[3] == "namespaces" && p[5] == "deployments" && r.URL.Query().Get("dryRun") == "All" {
		return 8
	}
	return 9
}

func TestOwnerObservationCostCounterClosedLabels(t *testing.T) {
	for _, tc := range []struct {
		method, target string
		want           int
	}{
		{http.MethodGet, "/api/v1/namespaces/anything", 0},
		{http.MethodGet, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/anything", 1},
		{http.MethodGet, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/anything", 2},
		{http.MethodGet, "/api/v1/namespaces/anything/serviceaccounts/anything", 3},
		{http.MethodGet, "/api/v1/namespaces/anything/pods/anything", 4},
		{http.MethodGet, "/api/v1/namespaces/anything/services/anything", 5},
		{http.MethodGet, "/apis/apps/v1/namespaces/anything/deployments/anything", 6},
		{http.MethodGet, "/apis/apps/v1/namespaces/anything/replicasets/anything", 7},
		{http.MethodGet, "/apis/discovery.k8s.io/v1/namespaces/anything/endpointslices?labelSelector=opaque", 8},
		{http.MethodPost, "/apis/authentication.k8s.io/v1/selfsubjectreviews", 8},
		{http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", 8},
		{http.MethodPut, "/apis/apps/v1/namespaces/anything/deployments/anything?dryRun=All", 8},
		{http.MethodPut, "/apis/apps/v1/namespaces/anything/deployments/anything", 9},
		{http.MethodGet, "/api/v1/namespaces/anything/secrets/never-retain-this", 9},
		{http.MethodGet, "/apis/unrecognized/v1/namespaces/anything/pods/anything", 9},
		{http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", 9},
		{http.MethodDelete, "/api/v1/namespaces/anything", 9},
	} {
		r, err := http.NewRequest(tc.method, "https://fixture.invalid"+tc.target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := ownerObservationCostLabel(r); got != tc.want {
			t.Errorf("closed label: got %d want %d", got, tc.want)
		}
	}
	for _, r := range []*http.Request{nil, {}, {URL: &url.URL{Path: "/opaque"}}} {
		if ownerObservationCostLabel(r) != 9 {
			t.Fatal("unknown request did not use fixed other label")
		}
	}
}

type ownerObservationCostBody struct{ reads, closes int }

func (b *ownerObservationCostBody) Read(p []byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *ownerObservationCostBody) Close() error               { b.closes++; return nil }

func TestOwnerObservationCostCounterTransparent(t *testing.T) {
	counter := &ownerObservationCostCounter{}
	input, output := &ownerObservationCostBody{}, &ownerObservationCostBody{}
	r, err := http.NewRequest(http.MethodGet, "https://fixture.invalid/api/v1/namespaces/opaque", input)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "synthetic-private-input")
	response := &http.Response{StatusCode: 403, Body: output}
	failure := errors.New("synthetic-private-error-not-retained")
	next := ownerProbeRoundTripper(func(got *http.Request) (*http.Response, error) {
		if got != r || got.Body != input || got.Header.Get("Authorization") != "synthetic-private-input" {
			t.Fatal("counter changed actual transport input")
		}
		return response, failure
	})
	wrapped := counter.wrap(false)(next)
	got, e := wrapped.RoundTrip(r)
	if got != response || e != failure || counter.snapshot() != (ownerObservationCostCount{}) {
		t.Fatal("unarmed transport changed result or retained work")
	}
	counter.arm()
	got, e = wrapped.RoundTrip(r)
	v := counter.snapshot()
	if got != response || e != failure || v.Requests[0][0] != 1 || v.HTTPFailures != 1 || v.TransportFailures != 1 {
		t.Fatal("armed counter changed result or lost failure counts")
	}
	if input.reads != 0 || input.closes != 0 || output.reads != 0 || output.closes != 0 {
		t.Fatal("diagnostic consumed or closed a payload")
	}
	raw, e := json.Marshal(v)
	if e != nil || bytes.Contains(raw, []byte("synthetic")) || bytes.Contains(raw, []byte("opaque")) || bytes.Contains(raw, []byte("fixture.invalid")) {
		t.Fatal("counter retained nonnumeric transport content")
	}
}

func TestOwnerObservationCostCounterConcurrent(t *testing.T) {
	counter := &ownerObservationCostCounter{}
	counter.arm()
	const calls = 32
	var joined sync.WaitGroup
	for i := range calls {
		joined.Go(func() {
			probe := i%2 != 0
			next := ownerProbeRoundTripper(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 200}, nil })
			r, _ := http.NewRequest(http.MethodGet, "https://fixture.invalid/api/v1/namespaces/opaque", nil)
			counter.wrap(probe)(next).RoundTrip(r)
			_ = counter.snapshot()
		})
	}
	joined.Wait()
	v := counter.snapshot()
	if v.Requests[0][0] != calls/2 || v.Requests[1][0] != calls/2 || v.HTTPFailures != 0 || v.TransportFailures != 0 {
		t.Fatal("concurrent observations lost or merged source counts")
	}
}
