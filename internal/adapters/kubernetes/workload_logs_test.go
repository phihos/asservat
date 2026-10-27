package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/targets"
)

// signalPod is a running Pod of the ADR-241 fixtures: its containers (with
// optional CPU/memory limits) and their statuses. A container named
// "never" is waiting without having run; "init-done" is an init container
// that finished long before any window.
func signalPod(name, rs string, started time.Time, containers ...string) map[string]any {
	pod := targetMetadata("Pod", name, "pod-"+name)
	m := pod["metadata"].(map[string]any)
	m["labels"] = map[string]string{"app": "checkout"}
	m["ownerReferences"] = []any{targetOwner("ReplicaSet", rs, rs+"-uid")}
	var specs, statuses []any
	for _, c := range containers {
		specs = append(specs, map[string]any{"name": c, "resources": map[string]any{"limits": map[string]string{"cpu": "500m", "memory": "256Mi"}}})
		state := map[string]any{"running": map[string]any{"startedAt": started.Format(time.RFC3339)}}
		if c == "never" {
			state = map[string]any{"waiting": map[string]any{"reason": "ContainerCreating"}}
		}
		statuses = append(statuses, map[string]any{"name": c, "restartCount": 0, "state": state})
	}
	pod["spec"] = map[string]any{"containers": specs, "initContainers": []any{map[string]any{"name": "init-done"}}}
	pod["status"] = map[string]any{"startTime": started.Format(time.RFC3339), "containerStatuses": statuses,
		"initContainerStatuses": []any{map[string]any{"name": "init-done", "state": map[string]any{"terminated": map[string]any{"reason": "Completed", "exitCode": 0, "finishedAt": started.Add(-time.Hour).Format(time.RFC3339)}}}}}
	return pod
}

// signalServer serves the workload chain of the ADR-241 fixtures; pods
// lists the Pods and extra serves every other path.
func signalServer(t *testing.T, clock *atomic.Int64, pods func() []any, extra func(http.ResponseWriter, *http.Request) bool) *PodTargets {
	return workloadClient(t, clock, func(w http.ResponseWriter, r *http.Request) {
		var object map[string]any
		switch {
		case r.URL.Path == "/api/v1/namespaces/payments":
			object = permissionNamespace("payments", "payments-uid")
		case r.URL.Path == "/apis/apps/v1/namespaces/payments/deployments/app":
			object = targetMetadata("Deployment", "app", "root-uid")
			object["metadata"].(map[string]any)["generation"] = 1
			object["spec"] = map[string]any{"selector": map[string]any{"matchLabels": map[string]string{"app": "checkout"}}}
		case r.URL.Path == "/api/v1/namespaces/payments/pods":
			object = map[string]any{"apiVersion": "v1", "kind": "PodList", "metadata": map[string]any{"resourceVersion": "list-rv"}, "items": pods()}
		case strings.HasPrefix(r.URL.Path, "/apis/apps/v1/namespaces/payments/replicasets/"):
			rs := strings.TrimPrefix(r.URL.Path, "/apis/apps/v1/namespaces/payments/replicasets/")
			object = targetMetadata("ReplicaSet", rs, rs+"-uid")
			owner := targetOwner("Deployment", "app", "root-uid")
			if rs == "foreign" {
				owner = targetOwner("Deployment", "other", "other-uid")
			}
			object["metadata"].(map[string]any)["ownerReferences"] = []any{owner}
		default:
			if !extra(w, r) {
				t.Errorf("unexpected read %s", r.URL.Path)
				w.WriteHeader(404)
			}
			return
		}
		permissionReply(w, object)
	})
}

func signalRequest() value.RestartRequest {
	return value.RestartRequest{WorkloadRequest: value.WorkloadRequest{ClusterID: permissionCluster, Namespace: "payments", Kind: "Deployment", Name: "app"}}
}

// ADR-241: a log observation reads one bounded pods/log GET per container
// that can have written into the window and returns per Pod only the number
// of matching records, the newest match second and an overlong flag. A read
// that failed or was truncated without a match is Unknown; a denied read or
// too many containers fail the poll; no record text leaves the region.
func TestWorkloadLogObservationCountsMatchingRecords(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	stamp := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339Nano) }
	for _, mode := range []string{"match", "json", "prefix", "truncated", "failed", "malformed", "denied", "too-many", "invalid-regexp"} {
		t.Run(mode, func(t *testing.T) {
			clock := &atomic.Int64{}
			clock.Store(now.UnixNano())
			var mu sync.Mutex
			reads := map[string]logQuery{}
			pods := func() []any {
				items := []any{signalPod("a", "rs", now.Add(-time.Hour), "app", "sidecar"), signalPod("b", "rs", now.Add(-time.Hour), "app", "never"), signalPod("c", "foreign", now.Add(-time.Hour), "app")}
				if mode == "too-many" {
					names := make([]string, value.MaxLogStreams)
					for i := range names {
						names[i] = fmt.Sprintf("c%d", i)
					}
					items = append(items, signalPod("d", "rs", now.Add(-time.Hour), names...))
				}
				return items
			}
			observer := signalServer(t, clock, pods, func(w http.ResponseWriter, r *http.Request) bool {
				var pod string
				if _, err := fmt.Sscanf(r.URL.Path, "/api/v1/namespaces/payments/pods/%s", &pod); err != nil || !strings.HasSuffix(pod, "/log") {
					return false
				}
				pod = strings.TrimSuffix(pod, "/log")
				q := r.URL.Query()
				mu.Lock()
				reads[pod+"/"+q.Get("container")] = logQuery{q.Get("sinceSeconds"), q.Get("timestamps"), q.Get("limitBytes")}
				mu.Unlock()
				if mode == "denied" {
					w.WriteHeader(403)
					permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "reason": "Forbidden", "status": "Failure", "code": 403})
					return true
				}
				w.Header().Set("Content-Type", "text/plain")
				switch pod + "/" + q.Get("container") {
				case "a/app":
					lines := []string{
						stamp(-40*time.Second) + " panic: timeout before the window MUST-NOT-LEAK",
						stamp(-20*time.Second) + " INFO request ok",
						stamp(-10*time.Second) + " panic: timeout talking to db MUST-NOT-LEAK",
						// A node clock ahead of the region counts as now.
						stamp(30*time.Second) + " panic: timeout from the future",
					}
					if mode == "json" {
						lines = []string{
							stamp(-10*time.Second) + ` {"level":"error","error":{"message":"panic: timeout MUST-NOT-LEAK"}}`,
							stamp(-9*time.Second) + ` {"level":"error","error":{"message":42}}`,
							stamp(-8*time.Second) + ` {"level":"error","msg":"panic: timeout outside the field"}`,
							stamp(-7*time.Second) + ` not json panic: timeout`,
						}
					}
					fmt.Fprint(w, strings.Join(lines, "\n")+"\n")
				case "a/sidecar":
					// One record longer than maxRecordBytes, then a short one.
					fmt.Fprint(w, stamp(-5*time.Second)+" panic: timeout "+strings.Repeat("x", 300)+"\n"+stamp(-4*time.Second)+" ok\n")
				case "b/app":
					switch mode {
					case "truncated":
						limit, _ := strconv.Atoi(q.Get("limitBytes"))
						line := stamp(-3*time.Second) + " INFO quiet\n"
						fmt.Fprint(w, strings.Repeat(line, limit/len(line)+1)[:limit])
					case "failed":
						w.WriteHeader(http.StatusInternalServerError)
					case "malformed":
						fmt.Fprint(w, "yesterday INFO quiet\n")
					default:
						fmt.Fprint(w, stamp(-3*time.Second)+" INFO quiet\n")
					}
				default:
					fmt.Fprint(w, "")
				}
				return true
			})
			r := signalRequest()
			r.Log = &value.LogMatch{Pattern: `panic: timeout`, Regexp: true, MaxRecordBytes: 256, WindowSeconds: 30}
			switch mode {
			case "json":
				r.Log.Regexp, r.Log.JSONField = false, "error.message"
			case "prefix":
				r.Log.MatchPrefix = true
			case "invalid-regexp":
				r.Log.Pattern = `(a)\1`
			}
			o, err := observer.ObserveWorkloadRestarts(context.Background(), r)
			switch mode {
			case "denied":
				if !errors.Is(err, value.ErrDenied) {
					t.Fatal("denied log read", err)
				}
				return
			case "too-many":
				if !errors.Is(err, value.ErrLimit) {
					t.Fatal("more than MaxLogStreams containers", err)
				}
				if len(reads) != 0 {
					t.Fatal("logs read before the stream bound", reads)
				}
				return
			case "invalid-regexp":
				if !errors.Is(err, value.ErrInvalid) {
					t.Fatal("non-RE2 pattern", err)
				}
				return
			}
			if err != nil || !o.Valid(now) || !o.Log || !o.Answers(r) || len(o.Pods) != 2 {
				t.Fatal(o, err)
			}
			// Running containers only: never-run and long-finished containers are
			// not read; the foreign Pod is not observed.
			if len(reads) != 3 || reads["b/never"] != (logQuery{}) || reads["a/init-done"] != (logQuery{}) || reads["c/app"] != (logQuery{}) {
				t.Fatal("log reads", reads)
			}
			// Bytes split per Pod's containers and across the observation.
			limit := strconv.Itoa(min(value.MaxLogPodBytes/2, value.MaxLogBytes/3))
			if a := reads["a/app"]; a != (logQuery{"30", "true", limit}) {
				t.Fatal("log GET parameters", a, limit)
			}
			a, b := o.Pods[0], o.Pods[1]
			switch mode {
			case "match":
				if a.ProbeFailures != 2 || a.ProbeLast != now.Unix() || !a.Overlong || a.Unknown {
					t.Fatal("matches", a)
				}
			case "json":
				if a.ProbeFailures != 1 || a.ProbeLast != now.Add(-10*time.Second).Unix() || !a.Overlong {
					t.Fatal("JSON field matches", a)
				}
			case "prefix":
				// The overlong record's prefix matches too.
				if a.ProbeFailures != 3 || !a.Overlong {
					t.Fatal("prefix matches", a)
				}
			}
			if mode == "truncated" || mode == "failed" || mode == "malformed" {
				if !b.Unknown || b.ProbeFailures != 0 || b.ProbeLast != 0 {
					t.Fatal("unprovable empty window", b)
				}
			} else if b.Unknown || b.ProbeFailures != 0 || b.Overlong {
				t.Fatal("quiet Pod", b)
			}
			if raw, _ := json.Marshal(o); strings.Contains(string(raw), "MUST-NOT-LEAK") || strings.Contains(string(raw), "panic") {
				t.Fatal("log text left the region", string(raw))
			}
		})
	}
}

// logQuery is the observed log query of one container.
type logQuery struct{ since, timestamps, limit string }

func TestLogJSONField(t *testing.T) {
	for record, want := range map[string]string{
		`{"a":{"b":"text"}}`: "text",
		`{"a":{"b":12.5}}`:   "12.5",
		`{"a":{"b":true}}`:   "true",
		`{"a":{"b":null}}`:   "",
		`{"a":{"b":[1]}}`:    "",
		`{"a":"flat"}`:       "",
		`["a"]`:              "",
		`{"a":{"b":"x"`:      "",
	} {
		got, ok := logJSONField([]byte(record), []string{"a", "b"})
		if string(got) != want || ok != (want != "") {
			t.Errorf("%s: %q %v", record, got, ok)
		}
	}
}
