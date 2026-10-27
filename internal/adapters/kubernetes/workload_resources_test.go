package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/targets"
)

// ADR-241: a resource observation adds one metrics.k8s.io PodMetrics LIST of
// the workload's selector. The level is the Pod's summed container usage
// (optionally over its finite limit) against the threshold; only the level
// and the sample second leave the region. A missing, stale, earlier-Pod or
// partial sample is Unknown; the metrics API being absent is unsupported and
// its being unavailable is Unknown for the poll, never zero.
func TestWorkloadResourceObservationEvaluatesMetrics(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	stamp := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	for _, mode := range []string{"ratio", "cores", "memory", "absent", "unavailable", "denied", "no-limit", "pod-limit", "malformed", "future"} {
		t.Run(mode, func(t *testing.T) {
			clock := &atomic.Int64{}
			clock.Store(now.UnixNano())
			var lists atomic.Int64
			pods := func() []any {
				// a: two containers, limit 2 × 500m CPU; b: restarted 20 s ago;
				// e: one running container missing from its sample; f: no sample;
				// g: stale sample; c: foreign.
				items := []any{signalPod("a", "rs", now.Add(-time.Hour), "app", "sidecar"), signalPod("b", "rs", now.Add(-20*time.Second), "app"),
					signalPod("e", "rs", now.Add(-time.Hour), "app", "sidecar"), signalPod("f", "rs", now.Add(-time.Hour), "app"), signalPod("g", "rs", now.Add(-time.Hour), "app"), signalPod("c", "foreign", now.Add(-time.Hour), "app")}
				switch mode {
				case "no-limit":
					delete(items[0].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[1].(map[string]any), "resources")
				case "pod-limit":
					// A Pod-level limit replaces the container sum.
					items[0].(map[string]any)["spec"].(map[string]any)["resources"] = map[string]any{"limits": map[string]string{"cpu": "4"}}
				}
				return items
			}
			observer := signalServer(t, clock, pods, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/apis/metrics.k8s.io/v1beta1/namespaces/payments/pods" {
					return false
				}
				lists.Add(1)
				if r.URL.Query().Get("labelSelector") != "app=checkout" {
					t.Errorf("unexpected PodMetrics LIST: %s", r.URL.RawQuery)
				}
				switch mode {
				case "absent":
					w.WriteHeader(404)
					permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "reason": "NotFound", "status": "Failure", "code": 404})
					return true
				case "unavailable":
					w.WriteHeader(503)
					permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "reason": "ServiceUnavailable", "status": "Failure", "code": 503})
					return true
				case "denied":
					w.WriteHeader(403)
					permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "reason": "Forbidden", "status": "Failure", "code": 403})
					return true
				}
				sample := func(pod, at string, usage ...string) map[string]any {
					var containers []any
					for i := 0; i+2 < len(usage)+1; i += 3 {
						containers = append(containers, map[string]any{"name": usage[i], "usage": map[string]string{"cpu": usage[i+1], "memory": usage[i+2]}})
					}
					return map[string]any{"metadata": map[string]any{"name": pod, "namespace": "payments", "labels": map[string]string{"secret": "MUST-NOT-LEAK"}}, "timestamp": at, "window": "15s", "containers": containers}
				}
				at := stamp(-10 * time.Second)
				if mode == "future" {
					at = stamp(20 * time.Second)
				}
				items := []any{
					// 0.9 of 1 core, 300 MiB.
					sample("a", at, "app", "600m", "200Mi", "sidecar", "300000000n", "100Mi"),
					// A sample from before Pod b started is of an earlier Pod b.
					sample("b", stamp(-40*time.Second), "app", "2", "1Gi"),
					sample("e", at, "app", "100m", "10Mi"),
					sample("g", stamp(-2*time.Minute), "app", "2", "1Gi"),
					sample("c", at, "app", "8", "8Gi"),
				}
				if mode == "malformed" {
					items[0] = sample("a", at, "app", "lots", "200Mi")
				}
				permissionReply(w, map[string]any{"apiVersion": "metrics.k8s.io/v1beta1", "kind": "PodMetricsList", "metadata": map[string]any{}, "items": items})
				return true
			})
			r := signalRequest()
			r.Resource = &value.ResourceCondition{Metric: value.MetricCPUQuotaRatio, Operator: "gt", Threshold: 0.8, MaxAgeSeconds: 60}
			switch mode {
			case "cores", "pod-limit":
				r.Resource.Metric, r.Resource.Threshold = value.MetricCPUCores, 1 // 0.9 cores
				if mode == "pod-limit" {
					r.Resource.Metric, r.Resource.Threshold = value.MetricCPUQuotaRatio, 0.2
				}
			case "memory":
				r.Resource.Metric, r.Resource.Operator, r.Resource.Threshold = value.MetricMemoryBytes, "lt", 200*1024*1024
			}
			o, err := observer.ObserveWorkloadRestarts(context.Background(), r)
			switch mode {
			case "absent", "no-limit":
				if !errors.Is(err, value.ErrUnsupported) {
					t.Fatal("capability gap", err)
				}
				return
			case "unavailable", "malformed":
				if !errors.Is(err, value.ErrUnavailable) {
					t.Fatal("unavailable metrics are Unknown", err)
				}
				return
			case "denied":
				if !errors.Is(err, value.ErrDenied) {
					t.Fatal("denied metrics", err)
				}
				return
			}
			if err != nil || !o.Valid(now) || !o.Resource || !o.Answers(r) || len(o.Pods) != 5 || lists.Load() != 1 {
				t.Fatal(o, err)
			}
			a := o.Pods[0]
			want := map[string]bool{"ratio": true, "cores": false, "memory": false, "pod-limit": true, "future": true}[mode]
			if want != (a.ProbeFailures == 1) || a.Unknown {
				t.Fatal("level", mode, a)
			}
			if want && a.ProbeLast != map[bool]int64{false: now.Add(-10 * time.Second).Unix(), true: now.Unix()}[mode == "future"] {
				t.Fatal("sample second", a)
			}
			for _, p := range o.Pods[1:] {
				if !p.Unknown || p.ProbeFailures != 0 {
					t.Fatal("unprovable sample is not Unknown", p)
				}
			}
			if raw, _ := json.Marshal(o); strings.Contains(string(raw), "MUST-NOT-LEAK") {
				t.Fatal("metric labels left the region", string(raw))
			}
		})
	}
}
