package contracts

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestClusterObservationMaximumClosedWire(t *testing.T) {
	// Deliberately cover the full accepted text-byte expansion, not only DNS
	// examples. Actual Kubernetes readers additionally validate source syntax.
	for _, ch := range []string{`"`, `\`, "<", "&"} {
		t.Run(fmt.Sprintf("char-%x", ch), func(t *testing.T) {
			full := func(n int) string { return strings.Repeat(ch, n) }
			r := ClusterObservationRequest{Format: ClusterObservationFormat, RequestID: strings.Repeat("1", 36), Challenge: strings.Repeat("2", 36), RootID: strings.Repeat("3", 36), ClusterID: strings.Repeat("4", 36), Purpose: ClusterObservationWorkload, RequestedAt: "2026-10-12T12:00:00.123456789Z", NotAfter: "2026-10-12T12:00:05.123456789Z", Namespace: &ClusterObservationNamespace{full(63), full(64)}, Workload: &ClusterObservationWorkloadRef{"StatefulSet", full(253), full(64)}, Keys: make([]string, 256)}
			labels := map[string]string{}
			for i := range r.Keys {
				r.Keys[i] = fmt.Sprintf("%03d", i) + full(250)
				labels[r.Keys[i]] = full(63)
			}
			body, e := EncodeClusterObservationRequest(r)
			if e != nil {
				t.Fatal("maximum request does not fit")
			}
			if _, e = DecodeClusterObservationRequest(body); e != nil {
				t.Fatal("maximum request rejected")
			}
			interval := ClusterObservationInterval{r.RequestedAt, r.NotAfter}
			v := ClusterObservationResult{Format: ClusterObservationFormat, RequestID: r.RequestID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Purpose: r.Purpose, RequestDigest: strings.Repeat("f", 64), Interval: interval, Workload: &ClusterObservationExactWorkload{Namespace: *r.Namespace, NamespaceResourceVersion: full(128), Labels: labels, NamespaceInterval: interval, Workload: *r.Workload, WorkloadResourceVersion: full(128), Interval: interval}}
			body, e = EncodeClusterObservationResult(v)
			if e != nil {
				t.Fatal("maximum exact observation does not fit")
			}
			if _, e = DecodeClusterObservationResult(body); e != nil {
				t.Fatal("maximum exact observation rejected")
			}
			t.Logf("bounded exact observation bytes=%d ceiling=%d", len(body), ClusterObservationBytes)
			page := ClusterObservationResult{Format: ClusterObservationFormat, RequestID: r.RequestID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Purpose: ClusterObservationWorkloads, RequestDigest: strings.Repeat("f", 64), Interval: interval, Workloads: &ClusterObservationWorkloadPage{ResourceVersion: full(128), Continue: full(8192), Items: make([]ClusterObservationWorkloadRef, 64)}}
			for i := range page.Workloads.Items {
				page.Workloads.Items[i] = ClusterObservationWorkloadRef{"StatefulSet", full(253), fmt.Sprintf("%03d", i) + full(61)}
			}
			body, e = EncodeClusterObservationResult(page)
			if e != nil {
				t.Fatal("maximum candidate page does not fit")
			}
			if _, e = DecodeClusterObservationResult(body); e != nil {
				t.Fatal("maximum candidate page rejected")
			}
		})
	}
}

func TestClusterObservationWireRejectsSmuggledFields(t *testing.T) {
	r := ClusterObservationRequest{Format: ClusterObservationFormat, RequestID: "request", Challenge: "challenge", RootID: "root", ClusterID: "cluster", Purpose: ClusterObservationNamespaces, RequestedAt: "2026-10-12T12:00:00Z", NotAfter: "2026-10-12T12:00:05Z"}
	body, e := EncodeClusterObservationRequest(r)
	if e != nil {
		t.Fatal(e)
	}
	for name, b := range map[string][]byte{
		"token":     append([]byte(`{"token":"must-not-be-read",`), body[1:]...),
		"url":       append([]byte(`{"url":"https://arbitrary.invalid",`), body[1:]...),
		"duplicate": append([]byte(`{"requestId":"other",`), body[1:]...),
		"alias":     bytes.Replace(body, []byte(`"requestId"`), []byte(`"RequestId"`), 1),
		"null":      bytes.Replace(body, []byte(`"challenge":"challenge"`), []byte(`"challenge":null`), 1),
		"missing":   bytes.Replace(body, []byte(`"challenge":"challenge",`), nil, 1),
		"trailing":  append(bytes.Clone(body), []byte(`{}`)...),
		"too-large": bytes.Repeat([]byte(" "), ClusterObservationBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeClusterObservationRequest(b); e == nil {
				t.Fatal("unsafe message accepted")
			}
		})
	}
}
