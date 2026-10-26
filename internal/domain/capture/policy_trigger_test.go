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

func probePolicy(minimum int) RestartPolicy {
	p := deltaPolicy()
	p.Reasons, p.ExitCodes = nil, nil
	p.Detector, p.ProbeType, p.MinimumFailures, p.ProbeWindow = DetectorProbe, "Readiness", minimum, time.Minute
	return p
}

func probeObservation(pods ...targets.PodRestarts) targets.RestartObservation {
	o := restartObservation(pods...)
	o.Probe = "Readiness"
	return o
}

func TestProbeDeltaFiresOnceOnRisingEdgeAndRearmsAfterAnEmptyWindow(t *testing.T) {
	p := probePolicy(2)
	if !p.Valid() || p.Kind() != DetectorProbe || p.Request().Probe != "Readiness" || p.Request().ProbeWindowSeconds != 60 || !p.Request().Valid() {
		t.Fatal("fixture probe policy", p.Request())
	}
	const t0 = 1792000000
	pod := func(failures, last int64) targets.PodRestarts {
		return targets.PodRestarts{Name: "api-a", UID: "a", ProbeFailures: failures, ProbeLast: last}
	}
	// A Pod already failing at its first observation is a disarmed baseline:
	// activation never fires and a continuing failure waits for recovery.
	next, fired := TriggerDelta(p, nil, probeObservation(pod(3, t0)))
	if len(fired) != 0 || next["a"] != (PodMark{t0, false}) {
		t.Fatal("failing baseline", next, fired)
	}
	if next, fired = TriggerDelta(p, next, probeObservation(pod(5, t0+10))); len(fired) != 0 || next["a"].Armed {
		t.Fatal("continuing failure fired without recovery", fired)
	}
	// An empty window re-arms.
	if next, fired = TriggerDelta(p, next, probeObservation(pod(0, t0+10))); len(fired) != 0 || !next["a"].Armed || next["a"].Value != t0+10 {
		t.Fatal("empty window did not re-arm", next)
	}
	// Below the minimum: no occurrence, still armed.
	if next, fired = TriggerDelta(p, next, probeObservation(pod(1, t0+100))); len(fired) != 0 || !next["a"].Armed {
		t.Fatal("below minimum", fired)
	}
	// Rising edge: one occurrence keyed by the newest failure second.
	next, fired = TriggerDelta(p, next, probeObservation(pod(2, t0+110)))
	if len(fired) != 1 || fired[0] != (RestartCandidate{PodUID: "a", Restarts: t0 + 110}) || next["a"] != (PodMark{t0 + 110, false}) {
		t.Fatal("rising edge", fired, next)
	}
	// Replay and continued failure do not fire again.
	for _, again := range []targets.PodRestarts{pod(2, t0+110), pod(4, t0+130)} {
		var f []RestartCandidate
		if next, f = TriggerDelta(p, next, probeObservation(again)); len(f) != 0 {
			t.Fatal("level fired twice", again)
		}
	}
	// A replayed older empty observation may re-arm, but the same newest
	// failure second never fires twice.
	stale, _ := TriggerDelta(p, next, probeObservation(pod(0, t0+110)))
	if _, f := TriggerDelta(p, stale, probeObservation(pod(2, t0+130))); len(f) != 0 {
		t.Fatal("stale re-arm fired the same failure again", f)
	}
	// A healthy first observation is an armed baseline.
	if next, fired = TriggerDelta(p, nil, probeObservation(pod(0, 0))); len(fired) != 0 || next["a"] != (PodMark{0, true}) {
		t.Fatal("healthy baseline", next)
	}
	if _, fired = TriggerDelta(p, next, probeObservation(pod(2, t0))); len(fired) != 1 {
		t.Fatal("first failure after a healthy baseline", fired)
	}
	// Exit watermarks pass through TriggerDelta unchanged.
	exit := deltaPolicy("Error")
	marks, f := TriggerDelta(exit, map[string]PodMark{"a": {Value: 1, Armed: true}}, restartObservation(targets.PodRestarts{Name: "api-a", UID: "a", Restarts: 2, Reason: "Error", ExitCode: 1}))
	if len(f) != 1 || marks["a"] != (PodMark{2, true}) {
		t.Fatal("exit via TriggerDelta", f, marks)
	}
}

func TestProbePolicyValidity(t *testing.T) {
	for name, mutate := range map[string]func(*RestartPolicy){
		"reasons":        func(p *RestartPolicy) { p.Reasons = []string{"Error"} },
		"probe-type":     func(p *RestartPolicy) { p.ProbeType = "Exec" },
		"minimum":        func(p *RestartPolicy) { p.MinimumFailures = 0 },
		"short-window":   func(p *RestartPolicy) { p.ProbeWindow = 15 * time.Second },
		"long-window":    func(p *RestartPolicy) { p.ProbeWindow = 6 * time.Minute },
		"partial-second": func(p *RestartPolicy) { p.ProbeWindow = 45500 * time.Millisecond },
		"unknown-kind":   func(p *RestartPolicy) { p.Detector = "log" },
	} {
		p := probePolicy(1)
		mutate(&p)
		if p.Valid() {
			t.Fatal(name, "accepted")
		}
	}
	exit := deltaPolicy("Error")
	exit.ProbeType = "Readiness"
	if exit.Valid() {
		t.Fatal("exit policy with probe fields accepted")
	}
	// A plain observation carries no probe data.
	o := restartObservation(targets.PodRestarts{Name: "x", UID: "x", ProbeFailures: 1, ProbeLast: 1792000000})
	if o.Valid(o.ObservedAt) {
		t.Fatal("probe data without a probe observation")
	}
	o.Probe = "Readiness"
	if !o.Valid(o.ObservedAt) {
		t.Fatal("probe observation rejected")
	}
	o.Pods[0].ProbeLast = 5
	if o.Valid(o.ObservedAt) {
		t.Fatal("probe failure second in the restart-count range accepted")
	}
}
