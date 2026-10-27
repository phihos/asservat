package capture

import (
	"math"
	"testing"

	"asservat.local/asservat/internal/domain/targets"
)

func logPolicy() RestartPolicy {
	p := deltaPolicy()
	p.Reasons, p.ExitCodes = nil, nil
	p.Detector, p.Log = DetectorLog, &targets.LogMatch{Pattern: "panic", MaxRecordBytes: 4096, WindowSeconds: 30}
	return p
}

func resourcePolicy() RestartPolicy {
	p := deltaPolicy()
	p.Reasons, p.ExitCodes = nil, nil
	p.Detector, p.Resource = DetectorResource, &targets.ResourceCondition{Metric: targets.MetricCPUQuotaRatio, Operator: "gt", Threshold: 0.8, MaxAgeSeconds: 60}
	return p
}

// ADR-241: log and resource detectors are levels on the probe path. A Pod
// reported Unknown keeps its watermark: it never fires, re-arms or becomes a
// baseline.
func TestLogAndResourceDeltasTreatUnknownAsNoChange(t *testing.T) {
	const t0 = 1792000000
	for _, p := range []RestartPolicy{logPolicy(), resourcePolicy()} {
		observe := func(pods ...targets.PodRestarts) targets.RestartObservation {
			o := restartObservation(pods...)
			o.Log, o.Resource = p.Detector == DetectorLog, p.Detector == DetectorResource
			if !o.Valid(o.ObservedAt) || !o.Answers(p.Request()) {
				t.Fatal(p.Detector, "fixture observation invalid")
			}
			return o
		}
		level := func(n, at int64) targets.PodRestarts {
			return targets.PodRestarts{Name: "api-a", UID: "a", ProbeFailures: n, ProbeLast: at}
		}
		unknown := targets.PodRestarts{Name: "api-a", UID: "a", Unknown: true}
		// Unknown at the first observation records no baseline.
		next, fired := TriggerDelta(p, nil, observe(unknown))
		if len(next) != 0 || len(fired) != 0 {
			t.Fatal(p.Detector, "unknown baseline", next, fired)
		}
		// A true baseline is disarmed; Unknown never re-arms it; a known false
		// poll does; the next rising edge fires once.
		next, _ = TriggerDelta(p, next, observe(level(1, t0)))
		if next["a"] != (PodMark{t0, false}) {
			t.Fatal(p.Detector, "true baseline", next)
		}
		next, fired = TriggerDelta(p, next, observe(unknown))
		if next["a"] != (PodMark{t0, false}) || len(fired) != 0 {
			t.Fatal(p.Detector, "unknown re-armed", next, fired)
		}
		next, _ = TriggerDelta(p, next, observe(level(0, 0)))
		if !next["a"].Armed {
			t.Fatal(p.Detector, "false poll did not re-arm", next)
		}
		next, fired = TriggerDelta(p, next, observe(unknown))
		if len(fired) != 0 || !next["a"].Armed {
			t.Fatal(p.Detector, "unknown fired or disarmed", next, fired)
		}
		next, fired = TriggerDelta(p, next, observe(level(3, t0+45)))
		if len(fired) != 1 || fired[0] != (RestartCandidate{PodUID: "a", Restarts: t0 + 45}) || next["a"].Armed {
			t.Fatal(p.Detector, "rising edge", fired, next)
		}
		// A repeated poll of the same level (same or later second) does not fire.
		for _, again := range []targets.PodRestarts{level(3, t0+45), level(4, t0+60)} {
			if next, fired = TriggerDelta(p, next, observe(again)); len(fired) != 0 {
				t.Fatal(p.Detector, "level fired twice")
			}
		}
	}
}

func TestLogAndResourceObservationValidity(t *testing.T) {
	const t0 = 1792000000
	o := restartObservation(targets.PodRestarts{Name: "api-a", UID: "a", Unknown: true})
	if o.Valid(o.ObservedAt) {
		t.Fatal("Unknown on an exit observation accepted")
	}
	o.Alert = true
	if o.Valid(o.ObservedAt) {
		t.Fatal("Unknown on an alert observation accepted")
	}
	o.Alert, o.Resource = false, true
	if !o.Valid(o.ObservedAt) {
		t.Fatal("Unknown resource Pod rejected")
	}
	o.Pods[0].Overlong = true
	if o.Valid(o.ObservedAt) {
		t.Fatal("overlong on a resource observation accepted")
	}
	o.Resource, o.Log = false, true
	if !o.Valid(o.ObservedAt) {
		t.Fatal("overlong log Pod rejected")
	}
	o.Pods[0].ProbeFailures, o.Pods[0].ProbeLast = 1, t0
	if o.Valid(o.ObservedAt) {
		t.Fatal("Unknown Pod with a level accepted")
	}
	o.Pods[0].Unknown = false
	o.Resource = true
	if o.Valid(o.ObservedAt) {
		t.Fatal("log and resource observation accepted")
	}
	// The observation must answer exactly the request's detector.
	o.Resource = false
	if o.Answers(resourcePolicy().Request()) || !o.Answers(logPolicy().Request()) {
		t.Fatal("answers")
	}
}

func TestLogAndResourcePolicyValidity(t *testing.T) {
	for name, mutate := range map[string]func(*RestartPolicy){
		"no-match": func(p *RestartPolicy) { p.Log = nil },
		"both": func(p *RestartPolicy) {
			p.Resource = &targets.ResourceCondition{Metric: "cpuCores", Operator: "gt", Threshold: 1, MaxAgeSeconds: 60}
		},
		"reasons":      func(p *RestartPolicy) { p.Reasons = []string{"Error"} },
		"empty":        func(p *RestartPolicy) { p.Log.Pattern = "" },
		"window":       func(p *RestartPolicy) { p.Log.WindowSeconds = 15 },
		"record":       func(p *RestartPolicy) { p.Log.MaxRecordBytes = 65537 },
		"json-prefix":  func(p *RestartPolicy) { p.Log.JSONField, p.Log.MatchPrefix = "msg", true },
		"json-empty":   func(p *RestartPolicy) { p.Log.JSONField = "a." },
		"invalid-utf8": func(p *RestartPolicy) { p.Log.Pattern = "\xff" },
	} {
		p := logPolicy()
		mutate(&p)
		if p.Valid() {
			t.Fatal(name, "accepted")
		}
	}
	for name, mutate := range map[string]func(*targets.ResourceCondition){
		"metric":    func(c *targets.ResourceCondition) { c.Metric = "cpuPSI" },
		"operator":  func(c *targets.ResourceCondition) { c.Operator = "eq" },
		"negative":  func(c *targets.ResourceCondition) { c.Threshold = -0.1 },
		"nan":       func(c *targets.ResourceCondition) { c.Threshold = math.NaN() },
		"infinite":  func(c *targets.ResourceCondition) { c.Threshold = math.Inf(1) },
		"young":     func(c *targets.ResourceCondition) { c.MaxAgeSeconds = 29 },
		"stale":     func(c *targets.ResourceCondition) { c.MaxAgeSeconds = 301 },
		"wrongkind": func(c *targets.ResourceCondition) { c.Metric = "" },
	} {
		p := resourcePolicy()
		mutate(p.Resource)
		if p.Valid() {
			t.Fatal(name, "accepted")
		}
	}
	c := targets.ResourceCondition{Metric: "memoryLimitRatio", Operator: "gte", Threshold: 1.2, MaxAgeSeconds: 60}
	if !c.Valid() || !c.Ratio() || c.Holds(1.1) || !c.Holds(1.2) || !c.Holds(1.5) {
		t.Fatal("utilization above one must not be clamped")
	}
	for op, want := range map[string][3]bool{"gt": {false, false, true}, "gte": {false, true, true}, "lt": {true, false, false}, "lte": {true, true, false}} {
		c := targets.ResourceCondition{Metric: "cpuCores", Operator: op, Threshold: 1, MaxAgeSeconds: 60}
		if got := [3]bool{c.Holds(0.5), c.Holds(1), c.Holds(1.5)}; got != want || c.Ratio() {
			t.Fatal(op, got)
		}
	}
	base := logPolicy().Request().WorkloadRequest
	if (targets.RestartRequest{WorkloadRequest: base, Log: logPolicy().Log, Probe: "Readiness", ProbeWindowSeconds: 60}).Valid() {
		t.Fatal("log with probe accepted")
	}
	if (targets.RestartRequest{WorkloadRequest: base, Resource: resourcePolicy().Resource, Alert: true}).Valid() {
		t.Fatal("resource with alert accepted")
	}
}
