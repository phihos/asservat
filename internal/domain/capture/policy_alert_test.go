package capture

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/targets"
)

func alertPolicy(labels map[string]string) RestartPolicy {
	p := deltaPolicy()
	p.Reasons, p.ExitCodes = nil, nil
	p.Detector, p.AlertLabels = DetectorAlert, labels
	return p
}

func alertObservation(pods ...targets.PodRestarts) targets.RestartObservation {
	o := restartObservation(pods...)
	o.Alert = true
	return o
}

// ADR-231: the alert detector reuses the probe level. A Pod is failing while
// a matching alert is active; one occurrence per rising edge keyed by the
// newest startsAt second; re-arm at the first poll with no matching alert.
func TestAlertDeltaUsesTheProbeLevel(t *testing.T) {
	p := alertPolicy(map[string]string{"alertname": "HighErrorRate"})
	r := p.Request()
	if !p.Valid() || p.Kind() != DetectorAlert || !r.Alert || r.AlertLabels["alertname"] != "HighErrorRate" || r.Probe != "" || !r.Valid() {
		t.Fatal("fixture alert policy", r)
	}
	const t0 = 1792000000
	pod := func(alerts, started int64) targets.PodRestarts {
		return targets.PodRestarts{Name: "api-a", UID: "a", ProbeFailures: alerts, ProbeLast: started}
	}
	// An alert already firing at activation is a disarmed baseline.
	next, fired := TriggerDelta(p, nil, alertObservation(pod(1, t0)))
	if len(fired) != 0 || next["a"] != (PodMark{t0, false}) {
		t.Fatal("firing baseline", next, fired)
	}
	// Resolution re-arms; the next episode (a later startsAt) fires once.
	next, _ = TriggerDelta(p, next, alertObservation(pod(0, 0)))
	if !next["a"].Armed || next["a"].Value != t0 {
		t.Fatal("resolution did not re-arm", next)
	}
	next, fired = TriggerDelta(p, next, alertObservation(pod(1, t0+600)))
	if len(fired) != 1 || fired[0] != (RestartCandidate{PodUID: "a", Restarts: t0 + 600}) || next["a"].Armed {
		t.Fatal("new episode", fired, next)
	}
	// A duplicate poll and a second alert of the same failing period do not fire.
	for _, again := range []targets.PodRestarts{pod(1, t0+600), pod(2, t0+620)} {
		if next, fired = TriggerDelta(p, next, alertObservation(again)); len(fired) != 0 {
			t.Fatal("level fired twice", again)
		}
	}
	// Alert data without the alert flag, or with a probe, is invalid.
	o := restartObservation(pod(1, t0))
	if o.Valid(o.ObservedAt) {
		t.Fatal("alert data without an alert observation")
	}
	o.Alert = true
	if !o.Valid(o.ObservedAt) {
		t.Fatal("alert observation rejected")
	}
	o.Probe = "Readiness"
	if o.Valid(o.ObservedAt) {
		t.Fatal("probe and alert observation accepted")
	}
}

func TestAlertPolicyValidity(t *testing.T) {
	for name, mutate := range map[string]func(*RestartPolicy){
		"reasons":     func(p *RestartPolicy) { p.Reasons = []string{"Error"} },
		"probe-type":  func(p *RestartPolicy) { p.ProbeType = "Readiness" },
		"minimum":     func(p *RestartPolicy) { p.MinimumFailures = 1 },
		"window":      func(p *RestartPolicy) { p.ProbeWindow = time.Minute },
		"pod-label":   func(p *RestartPolicy) { p.AlertLabels = map[string]string{"pod": "x"} },
		"bad-name":    func(p *RestartPolicy) { p.AlertLabels = map[string]string{"1x": "x"} },
		"empty-value": func(p *RestartPolicy) { p.AlertLabels = map[string]string{"severity": ""} },
	} {
		p := alertPolicy(nil)
		mutate(&p)
		if p.Valid() {
			t.Fatal(name, "accepted")
		}
	}
	if !alertPolicy(nil).Valid() {
		t.Fatal("alert policy without labels rejected")
	}
	probe := probePolicy(1)
	probe.AlertLabels = map[string]string{"severity": "critical"}
	if probe.Valid() {
		t.Fatal("probe policy with alert labels accepted")
	}
	base := probe.Request().WorkloadRequest
	if (targets.RestartRequest{WorkloadRequest: base, AlertLabels: map[string]string{"severity": "critical"}}).Valid() {
		t.Fatal("labels without alert accepted")
	}
	if (targets.RestartRequest{WorkloadRequest: base, Alert: true, Probe: "Readiness", ProbeWindowSeconds: 60}).Valid() {
		t.Fatal("alert with probe accepted")
	}
}
