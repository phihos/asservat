package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/targets"
)

func TestAlertmanagerURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"http://alertmanager-operated.monitoring.svc:9093": true,
		"https://alertmanager.monitoring.svc/alertmanager": true,
		"http://alertmanager.monitoring.svc:9093/":         true,
		"":                                     false,
		"ftp://alertmanager:9093":              false,
		"http://user:secret@alertmanager:9093": false,
		"http://alertmanager:9093/?x=1":        false,
		"http://alertmanager:9093/#frag":       false,
		"alertmanager:9093":                    false,
		"http:///api":                          false,
		"http://alertmanager:9093/" + strings.Repeat("a", 512): false,
	} {
		if AlertmanagerURL(raw) != ok {
			t.Errorf("%q: want %v", raw, ok)
		}
	}
}

// ADR-231: an alert policy's poll adds one GET of the cluster's Alertmanager
// v2 alerts API. Alerts map to Pods by their namespace and pod labels; no
// label or annotation text leaves the region; every failure is Unknown.
func TestWorkloadAlertObservationMapsActiveAlertsToPods(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339Nano) }
	for _, mode := range []string{"alerts", "future", "unconfigured", "unreachable", "status", "redirect", "oversized", "too-many", "malformed", "not-array", "unknown-state", "foreign-malformed"} {
		t.Run(mode, func(t *testing.T) {
			var gets atomic.Int64
			alert := func(labels map[string]string, starts, state string) map[string]any {
				return map[string]any{"labels": labels, "annotations": map[string]string{"description": "MUST-NOT-LEAK"}, "startsAt": starts, "endsAt": at(time.Hour),
					"fingerprint": "0123456789abcdef", "generatorURL": "http://prometheus/MUST-NOT-LEAK", "receivers": []any{map[string]string{"name": "team"}},
					"status": map[string]any{"state": state, "silencedBy": []any{}, "inhibitedBy": []any{}}, "updatedAt": at(0)}
			}
			labels := func(pod string, extra ...string) map[string]string {
				l := map[string]string{"alertname": "HighErrorRate", "namespace": "payments", "severity": "critical", "secret": "MUST-NOT-LEAK"}
				if pod != "" {
					l["pod"] = pod
				}
				for i := 0; i+1 < len(extra); i += 2 {
					l[extra[i]] = extra[i+1]
				}
				return l
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gets.Add(1)
				q := r.URL.Query()
				if r.Method != http.MethodGet || r.URL.Path != "/prefix/api/v2/alerts" || q.Get("active") != "true" || q.Get("silenced") != "false" || q.Get("inhibited") != "false" || len(q["filter"]) != 2 || q["filter"][0] != `namespace="payments"` || !strings.HasPrefix(q["filter"][1], `pod=~"`) || strings.Count(q["filter"][1], "|") != 1 || r.Header.Get("Authorization") != "" {
					t.Errorf("unexpected Alertmanager request %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
				}
				switch mode {
				case "status":
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				case "redirect":
					http.Redirect(w, r, "http://elsewhere.invalid/api/v2/alerts", http.StatusFound)
					return
				case "oversized":
					_, _ = w.Write([]byte("[" + strings.Repeat(" ", alertBodyLimit) + "]"))
					return
				case "not-array":
					_, _ = w.Write([]byte(`{"alerts":[]}`))
					return
				}
				items := []any{
					// Two alerts on Pod a: counted twice, newest startsAt wins.
					alert(labels("a"), at(-10*time.Minute), "active"),
					alert(labels("a", "alertname", "Latency"), at(-2*time.Minute), "active"),
					// A label mismatch, a foreign namespace, a foreign Pod, a Pod
					// of another ReplicaSet, a workload-level alert without a pod
					// label and a suppressed alert are ignored.
					alert(labels("b", "severity", "warning"), at(-time.Minute), "active"),
					alert(map[string]string{"alertname": "HighErrorRate", "severity": "critical", "namespace": "other", "pod": "b"}, at(-time.Minute), "active"),
					alert(labels("unknown-pod"), at(-time.Minute), "active"),
					alert(labels("c"), at(-time.Minute), "active"),
					alert(labels(""), at(-time.Minute), "active"),
					alert(labels("b"), at(-time.Minute), "suppressed"),
				}
				switch mode {
				case "future":
					// A skewed source clock counts as now.
					items = append(items, alert(labels("b"), at(time.Hour), "unprocessed"))
				case "too-many":
					for len(items) <= alertLimit {
						items = append(items, alert(labels("unknown-pod"), at(-time.Minute), "active"))
					}
				case "malformed":
					items = append(items, alert(labels("b"), "not-a-time", "active"))
				case "unknown-state":
					items = append(items, alert(labels("b"), at(-time.Minute), "resolved"))
				case "foreign-malformed":
					// Malformed alerts of other workloads are ignored.
					items = append(items, alert(nil, "not-a-time", "active"), alert(labels("unknown-pod"), "not-a-time", "resolved"))
				}
				_ = json.NewEncoder(w).Encode(items)
			}))
			base := server.URL + "/prefix"
			if mode == "unreachable" {
				server.Close()
			} else {
				defer server.Close()
			}
			clock := &atomic.Int64{}
			clock.Store(now.UnixNano())
			observer := workloadClient(t, clock, func(w http.ResponseWriter, r *http.Request) {
				var object map[string]any
				switch r.URL.Path {
				case "/api/v1/namespaces/payments":
					object = permissionNamespace("payments", "payments-uid")
				case "/apis/apps/v1/namespaces/payments/deployments/app":
					object = targetMetadata("Deployment", "app", "root-uid")
					object["metadata"].(map[string]any)["generation"] = 1
					object["spec"] = map[string]any{"selector": map[string]any{"matchLabels": map[string]string{"app": "checkout"}}}
				case "/api/v1/namespaces/payments/pods":
					items := []any{restartFixturePod("a", "rs", 0, "", 0, false), restartFixturePod("b", "rs", 0, "", 0, false), restartFixturePod("c", "foreign", 0, "", 0, false)}
					object = map[string]any{"apiVersion": "v1", "kind": "PodList", "metadata": map[string]any{"resourceVersion": "list-rv"}, "items": items}
				default:
					var rs string
					if _, err := fmt.Sscanf(r.URL.Path, "/apis/apps/v1/namespaces/payments/replicasets/%s", &rs); err != nil {
						t.Errorf("unexpected read %s", r.URL.Path)
						w.WriteHeader(404)
						return
					}
					object = targetMetadata("ReplicaSet", rs, rs+"-uid")
					owner := targetOwner("Deployment", "app", "root-uid")
					if rs == "foreign" {
						owner = targetOwner("Deployment", "other", "other-uid")
					}
					object["metadata"].(map[string]any)["ownerReferences"] = []any{owner}
				}
				permissionReply(w, object)
			})
			if mode != "unconfigured" {
				alerts, err := NewAlertmanager(base)
				if err != nil {
					t.Fatal(err)
				}
				observer = observer.WithAlertmanager(alerts)
			}
			o, err := observer.ObserveWorkloadRestarts(context.Background(), value.RestartRequest{WorkloadRequest: value.WorkloadRequest{ClusterID: permissionCluster, Namespace: "payments", Kind: "Deployment", Name: "app"}, Alert: true, AlertLabels: map[string]string{"severity": "critical"}})
			switch mode {
			case "unconfigured":
				if !errors.Is(err, value.ErrUnsupported) {
					t.Fatal("alert observation without an Alertmanager", err)
				}
				return
			case "oversized", "too-many":
				if !errors.Is(err, value.ErrLimit) {
					t.Fatal("unbounded Alertmanager answer accepted", err)
				}
				return
			case "unreachable", "status", "redirect", "malformed", "not-array", "unknown-state":
				if !errors.Is(err, value.ErrUnavailable) {
					t.Fatal("failed Alertmanager read was not Unknown", err)
				}
				return
			}
			bAlerts, bLast := int64(0), int64(0)
			if mode == "future" {
				bAlerts, bLast = 1, now.Unix()
			}
			if err != nil || !o.Valid(now) || !o.Alert || o.Probe != "" || len(o.Pods) != 2 || gets.Load() != 1 {
				t.Fatal(o, err)
			}
			a, b := o.Pods[0], o.Pods[1]
			if a.UID != "pod-a" || a.ProbeFailures != 2 || a.ProbeLast != now.Add(-2*time.Minute).Unix() || b.UID != "pod-b" || b.ProbeFailures != bAlerts || b.ProbeLast != bLast {
				t.Fatal("alert levels", o.Pods)
			}
			raw, _ := json.Marshal(o)
			for _, leak := range []string{"MUST-NOT-LEAK", "HighErrorRate", "critical", "0123456789abcdef"} {
				if strings.Contains(string(raw), leak) {
					t.Fatal("alert text left the region", leak, string(raw))
				}
			}
		})
	}
}
