package capture

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/targets"
)

func deltaPolicy(reasons ...string) RestartPolicy {
	return RestartPolicy{ClusterID: "11111111-1111-4111-8111-111111111111", Namespace: "apps", WorkloadKind: "Deployment", WorkloadName: "api", Reasons: reasons, ExitCodes: []int32{1, 137}, Interval: 5 * time.Minute, Burst: 2, RetentionSeconds: 3600, ObservedPods: targets.MaxRestartPods}
}

func restartObservation(pods ...targets.PodRestarts) targets.RestartObservation {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	return targets.RestartObservation{ClusterID: "11111111-1111-4111-8111-111111111111", Namespace: configuration.NamespaceRef{Name: "apps", UID: "ns"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "wl"}, Pods: pods, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
}

func TestRestartDeltaFiresOnlyOnNewMatchingRestarts(t *testing.T) {
	p := deltaPolicy("Error", "OOMKilled")
	if !p.Valid() {
		t.Fatal("fixture policy")
	}
	a := targets.PodRestarts{Name: "api-a", UID: "a", Restarts: 2, Reason: "Error", ExitCode: 137}
	// First observation: baseline only, even of an already restarted Pod.
	next, fired := RestartDelta(p, nil, restartObservation(a))
	if len(fired) != 0 || next["a"] != 2 {
		t.Fatal("first observation fired", fired)
	}
	// Replay of the same counter is a no-op.
	if _, fired = RestartDelta(p, next, restartObservation(a)); len(fired) != 0 {
		t.Fatal("replay fired")
	}
	// A missed poll: one occurrence coalesces three restarts.
	a.Restarts = 5
	next, fired = RestartDelta(p, next, restartObservation(a))
	if len(fired) != 1 || fired[0].PodUID != "a" || fired[0].Restarts != 5 || fired[0].Missed != 2 || next["a"] != 5 {
		t.Fatal("missed poll", fired)
	}
	// An older (lower) counter never fires and never lowers the watermark.
	a.Restarts = 3
	if next2, fired := RestartDelta(p, next, restartObservation(a)); len(fired) != 0 || next2["a"] != 5 {
		t.Fatal("lower counter", fired, next2)
	}
	// UID replacement: a new Pod under the same name is a new baseline; the
	// vanished UID drops out of the watermarks.
	b := targets.PodRestarts{Name: "api-a", UID: "b", Restarts: 1, Reason: "Error", ExitCode: 137}
	next, fired = RestartDelta(p, next, restartObservation(b))
	if len(fired) != 0 || len(next) != 1 || next["b"] != 1 {
		t.Fatal("UID replacement", fired, next)
	}
	for _, c := range []struct {
		name  string
		pod   targets.PodRestarts
		fires bool
	}{
		{"matching", targets.PodRestarts{Name: "x", UID: "b", Restarts: 2, Reason: "OOMKilled", ExitCode: 137}, true},
		{"other-reason", targets.PodRestarts{Name: "x", UID: "b", Restarts: 2, Reason: "Completed", ExitCode: 137}, false},
		{"other-exit-code", targets.PodRestarts{Name: "x", UID: "b", Restarts: 2, Reason: "Error", ExitCode: 2}, false},
		{"crash-loop-not-selected", targets.PodRestarts{Name: "x", UID: "b", Restarts: 2, Reason: "Other", ExitCode: 137, Waiting: true}, false},
	} {
		if _, fired := RestartDelta(p, next, restartObservation(c.pod)); (len(fired) == 1) != c.fires {
			t.Fatal(c.name, fired)
		}
	}
	loop := deltaPolicy("CrashLoopBackOff")
	loop.ExitCodes = nil
	if _, fired := RestartDelta(loop, next, restartObservation(targets.PodRestarts{Name: "x", UID: "b", Restarts: 2, Reason: "Error", ExitCode: 1, Waiting: true})); len(fired) != 1 {
		t.Fatal("CrashLoopBackOff wait not matched")
	}
}
