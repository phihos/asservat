package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func argumentRecordingFixture() *artifact.Recording {
	return &artifact.Recording{Kind: "syscallTrace", Profile: "arguments", Composition: []byte("{}"), DurationMillis: 10000, MaxBytes: 64 << 10, Syscalls: &artifact.RecordingSyscalls{Names: []string{"openat"}, MaxEvents: 1000, MaxEventsPerSecond: 100, MaxTrackedThreads: 4096}, Arguments: &artifact.RecordingArguments{ProgramDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AccountingRule: artifact.Digest{3}, MaxProbeBytes: 512, MaxBytesPerEvent: 128, MaxBytesPerSecond: 1024}}
}
func TestFiniteManualArgumentsReserveBothPoolsBeforeRead(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	g := Grant{Kind: GrantAdHocCapture, Decision: &GrantDecision{Approved: true}, ExpiresAt: now.Add(time.Hour)}
	limits := ObservationLimits{MaxSessionSeconds: 70, MaxObservedBytes: 1 << 20, MaxObservedEvents: 10000, MaxBytesPerSecond: 1024, MaxConcurrentSessions: 1}
	r := argumentRecordingFixture()
	plan, err := PlanFiniteAdHocArgumentObservation(g, limits, r, 0, now.Add(10*time.Second), now.Add(time.Minute), now)
	if err != nil || plan.EventCredit != 22 || plan.ByteCredit != 11264 || plan.EventsPerSecond != 100 || plan.BytesPerSecond != 1024 || !plan.LatestStart.Equal(now.Add(10*time.Second)) {
		t.Fatal("conservative one-burst dual credit", plan, err)
	}
	for _, mode := range []string{"no events", "no bytes", "unapproved", "revoked", "expired", "busy", "insufficient time", "byte rate", "metadata", "no pins"} {
		t.Run(mode, func(t *testing.T) {
			grant, l, recording, active, hard := g, limits, r.Clone(), int64(0), now.Add(time.Minute)
			switch mode {
			case "no events":
				l.MaxObservedEvents = 0
			case "no bytes":
				l.MaxObservedBytes = 511
			case "unapproved":
				grant.Decision = nil
			case "revoked":
				grant.RevokedAt = now
			case "expired":
				grant.ExpiresAt = now
			case "busy":
				active = 1
			case "insufficient time":
				hard = now.Add(10 * time.Second)
			case "byte rate":
				l.MaxBytesPerSecond = 512
			case "metadata":
				recording.Profile = "metadata"
			case "no pins":
				recording.Arguments = nil
			}
			if _, err := PlanFiniteAdHocArgumentObservation(grant, l, recording, active, now.Add(10*time.Second), hard, now); err == nil {
				t.Fatal("unfunded or unapproved argument read planned")
			}
		})
	}
	r.DurationMillis = 60000
	p, err := PlanFiniteAdHocArgumentObservation(g, limits, r, 0, now.Add(10*time.Second), now.Add(70*time.Second), now)
	if err != nil || p.Duration != time.Minute || !p.Until.Equal(now.Add(70*time.Second)) {
		t.Fatal("full specified finite duration", p, err)
	}
}

func TestFinitePolicyArgumentsPreserveIndependentAggregateSpend(t *testing.T) {
	g, a, target, now := finitePolicyObservationFixture(t)
	a.Limits.MaxObservedEvents = 1000
	g.Policy.Authority = a
	g.Policy.Limits.MaxObservedEvents = 100
	g.Policy.Observation.MaxObservedEvents = 100
	r := argumentRecordingFixture()
	g.PolicySpend.ObservedEvents = 95
	p, err := PlanFinitePolicyArgumentObservation(g, a, target, r, 1<<20, 1000, 0, now.Add(10*time.Second), now.Add(time.Minute), now)
	if err != nil || p.EventCredit != 5 {
		t.Fatal("grant remaining events ignored", p, err)
	}
	p, err = PlanFinitePolicyArgumentObservation(g, a, target, r, 1<<20, 3, 0, now.Add(10*time.Second), now.Add(time.Minute), now)
	if err != nil || p.EventCredit != 3 {
		t.Fatal("accepted policy remaining events ignored", p, err)
	}
	g.PolicySpend.ObservedEvents = 100
	if _, err = PlanFinitePolicyArgumentObservation(g, a, target, r, 1<<20, 1000, 0, now.Add(10*time.Second), now.Add(time.Minute), now); err == nil {
		t.Fatal("new session refilled grant events")
	}
	if err = CheckPolicyObservationStart(g, a, target, 10*time.Second, 512, 0, now); err != nil {
		t.Fatal("exhausted events incorrectly consumed remaining packet byte authority", err)
	}
}

func TestLegacyAutomationAndPolicySpendOmitEventDefaults(t *testing.T) {
	for _, v := range []any{AutomationLimits{MaxExecutions: 1, MaxBytes: 2, MaxObservedBytes: 3}, AutomationEnvelope{AllowedActions: []string{"packetCapture"}, MaxLifetimeSeconds: 3600, MaxExecutions: 1, MaxBytes: 2, MaxObservedBytes: 3}, PolicyGrantSpend{Executions: 1, CollectedBytes: 2, ObservedBytes: 3}} {
		raw, err := json.Marshal(v)
		if err != nil || strings.Contains(string(raw), "Events") {
			t.Fatal("legacy zero event encoding changed", string(raw), err)
		}
	}
}
