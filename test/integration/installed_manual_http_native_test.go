package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/httpheaders"
	"asservat.local/asservat/internal/domain/artifact"
	"k8s.io/client-go/rest"
)

// ADR-282 manual-http focus: the namespace CaptureProfile "http-capture" v1
// is the builtin network profile republished with an httpHeaders profile at
// the specified defaults (and maxima): 1024 flows, 32 KiB header block,
// 256 KiB per flow, 16 MiB total reassembly, 30 s idle timeout.
const (
	manualHTTPProfileName    = "http-capture"
	manualHTTPProfileVersion = "v1"
	// manualHTTPMarker is synthetic: the traffic sends it in the URL query and
	// a request Cookie, and the fixture workload returns it in Set-Cookie. No
	// byte of it may reach the projection.
	manualHTTPMarker = "synthetic-http-secret-5d2c91"
)

// manualHTTPLimits are the projector limits the profile below selects.
func manualHTTPLimits() httpheaders.Limits {
	return httpheaders.Limits{MaxFlows: 1024, MaxHeaderBytes: 32 << 10, MaxFlowBytes: 256 << 10, MaxTotalBytes: 16 << 20, IdleTimeout: 30 * time.Second}
}

// manualHTTPProfileDefinition copies the builtin network-connections v1
// definition with an httpHeaders profile and sensitiveRead impact.
func manualHTTPProfileDefinition() (map[string]any, error) {
	l := manualHTTPLimits()
	return builtinNetworkDefinitionWith(map[string]any{"kind": "httpHeaders", "protocol": "http1",
		"projectionRef": map[string]any{"name": "http-response-headers", "version": "v1"},
		"maxFlows":      l.MaxFlows, "maxHeaderBytes": l.MaxHeaderBytes,
		"maxReassemblyBytesPerFlow": l.MaxFlowBytes, "maxReassemblyBytes": l.MaxTotalBytes, "idleTimeout": "30s"})
}

// manualHTTPArguments is the public finite HTTP header request: one
// on-trigger action, no history, five seconds after start, a reviewed filter.
// Unlike raw output, the extract downloads under ordinary eligibility, so the
// request carries no result_access.
func manualHTTPArguments(cluster, namespace, workload string) map[string]any {
	return map[string]any{
		"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"requested_retention_seconds": 600,
		"profile_composition": map[string]any{
			"components": []any{map[string]any{
				"id":         "network",
				"profileRef": map[string]string{"catalog": "namespace", "name": manualHTTPProfileName, "version": manualHTTPProfileVersion},
				"overrides": []any{
					map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"},
					map[string]any{"actionID": "sample", "field": "actionExecutionMode", "value": "onTrigger"},
					map[string]any{"actionID": "sample", "field": "packetBefore", "value": "0s"},
					map[string]any{"actionID": "sample", "field": "packetAfter", "value": "5s"},
					map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "15s"},
				},
			}},
			"maxTotalBytes": 16 << 20,
			"maxDuration":   "15s",
		},
	}
}

// publishManualHTTPProfile is the workload team's step, as for manual-raw.
func publishManualHTTPProfile(t *testing.T, ctx context.Context, regionalConfig, namespace string) {
	t.Helper()
	definition, err := manualHTTPProfileDefinition()
	if err != nil {
		t.Fatal(err)
	}
	publishNamespaceCaptureProfile(t, ctx, regionalConfig, namespace, manualHTTPProfileName, manualHTTPProfileVersion, definition)
}

// manualHTTPTraffic is one request of the focus's traffic loop: the fixture
// workload's /log?headers=1 answers with Connection: close (so every request
// opens a new connection whose SYN the finite recording can see, instead of
// reusing the API server's kept-alive proxy connection), a text body and a
// Set-Cookie carrying the marker. The request carries the marker in its
// query and a Cookie.
func manualHTTPTraffic(r *rest.Request) *rest.Request {
	return r.Param("line", manualHTTPMarker).Param("headers", "1").SetHeader("Cookie", "session="+manualHTTPMarker)
}

// manualHTTPExtension is the registered native filename extension.
func manualHTTPExtension(t *testing.T) string {
	t.Helper()
	native, ok := artifact.LookupNativeType(artifact.HTTPHeadersArtifact)
	if !ok || native.Extension == "" {
		t.Fatal("httpHeaders native type is not registered")
	}
	return native.Extension
}

// manualHTTPSummary is what the focus logs from the downloaded projection.
type manualHTTPSummary struct {
	Records, Answered int
	Counters          httpheaders.Counters
}

// checkManualHTTPProjection strictly decodes the downloaded projection,
// rechecks it with the publisher's independent check, and requires at least
// one GET record with a status, only content-type/content-length header
// names, and no byte of the synthetic marker or a credential header name.
func checkManualHTTPProjection(native []byte) (manualHTTPSummary, error) {
	var s manualHTTPSummary
	decoder := json.NewDecoder(bytes.NewReader(native))
	decoder.DisallowUnknownFields()
	var p httpheaders.Projection
	if err := decoder.Decode(&p); err != nil {
		return s, fmt.Errorf("projection does not decode strictly: %w", err)
	}
	s.Counters = p.Counters
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return s, errors.New("projection has trailing data")
	}
	l := manualHTTPLimits()
	want := httpheaders.LimitsRecord{MaxFlows: l.MaxFlows, MaxHeaderBytes: l.MaxHeaderBytes, MaxFlowBytes: l.MaxFlowBytes, MaxTotalBytes: l.MaxTotalBytes, IdleTimeoutSeconds: int64(l.IdleTimeout / time.Second), Snaplen: httpheaders.Snaplen}
	if p.Format != artifact.HTTPHeadersFormat || p.Protocol != "http1" || p.Limits != want {
		return s, fmt.Errorf("projection format %q protocol %q limits %+v", p.Format, p.Protocol, p.Limits)
	}
	if _, err := httpheaders.CheckProjection(bytes.NewReader(native), l, artifact.HTTPHeadersNativeLimit); err != nil {
		return s, fmt.Errorf("independent projection check: %w", err)
	}
	for _, r := range p.Records {
		for _, h := range r.Headers {
			if h.Name != "content-type" && h.Name != "content-length" {
				return s, fmt.Errorf("unapproved header name %q", h.Name)
			}
		}
		if r.Method == "GET" && r.Status != 0 {
			s.Answered++
		}
	}
	lower := bytes.ToLower(native)
	for _, forbidden := range []string{manualHTTPMarker, "cookie", "authorization"} {
		if bytes.Contains(lower, []byte(forbidden)) {
			return s, fmt.Errorf("projection contains %q", forbidden)
		}
	}
	s.Records = len(p.Records)
	if s.Answered == 0 {
		return s, errors.New("no GET record with a status")
	}
	return s, nil
}

// qualifyManualHTTPProjection writes the native projection and checks it.
func qualifyManualHTTPProjection(t *testing.T, native []byte) manualHTTPSummary {
	t.Helper()
	if err := os.WriteFile("../results/manual-http.json", native, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := checkManualHTTPProjection(native)
	if err != nil {
		t.Fatalf("HTTP header projection: %v; counters %+v", err, s.Counters)
	}
	return s
}
