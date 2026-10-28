package postgres

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"bytes"
)

func policyObservationRowFixture() custodydb.PolicyObservationSession {
	now := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	row := custodydb.PolicyObservationSession{
		ID: id("11111111-1111-4111-8111-111111111111"), RootID: id("22222222-2222-4222-8222-222222222222"), PolicyUid: "policy", AcceptanceID: id("33333333-3333-4333-8333-333333333333"), GrantID: id("44444444-4444-4444-8444-444444444444"), CaptureID: id("55555555-5555-4555-8555-555555555555"), AttemptID: id("66666666-6666-4666-8666-666666666666"), Fence: id("77777777-7777-4777-8777-777777777777"),
		ActionID: "packet", PodUid: "actual-workload-pod", NodeUid: "actual-node", BootID: "actual-boot", CollectorPodUid: "actual-collector", CollectorEpoch: "actual-process",
		ExpectationDigest: make([]byte, 32), ProgramDigest: make([]byte, 32), AccountingRule: observationRuleBytes(), SourceObservedAt: ts(now.Add(-time.Second)), SourceFreshUntil: ts(now.Add(4 * time.Second)),
		StartedAt: ts(now), SessionUntil: ts(now.Add(20 * time.Second)), LeaseUntil: ts(now.Add(20 * time.Second)), StartBy: ts(now.Add(5 * time.Second)), DurationMillis: 15000, Sequence: 1, Credit: 256 << 20, MaxBytesPerSecond: 16 << 20,
	}
	row.ExpectationDigest[0] = 1
	row.ProgramDigest[0] = 2
	row.BindingScope = policyObservationScope(row)
	return row
}

func TestPolicyObservationPermitPinsOriginalSQLTuple(t *testing.T) {
	row := policyObservationRowFixture()
	permit, err := policyObservationPermit(row)
	if err != nil || !permit.Binding.Valid() || !permit.Lease().Valid(row.StartedAt.Time) || permit.Credit != 256<<20 || permit.BytesPerSecond != 16<<20 || permit.Duration != 15*time.Second || !permit.StartBy.Equal(row.StartBy.Time) || permit.Binding.AccountingRule != collector.ObservationAccountingRule() {
		t.Fatalf("original finite permit: %+v %v", permit, err)
	}
	// The SQL row's JSON round trip preserves the fixed scope. Its original fit
	// remains independent from a later caller clock/source-observation interval.
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	var restored custodydb.PolicyObservationSession
	if err = json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	replay, err := policyObservationPermit(restored)
	if err != nil || replay != permit {
		t.Fatalf("replay changed original reservation: %+v %v", replay, err)
	}
	if replay.Lease().Valid(row.LeaseUntil.Time) {
		t.Fatal("original lease revived at its end")
	}
	for _, mode := range []string{"grant", "acceptance", "capture", "attempt", "session", "fence", "pod", "node", "boot", "collector", "epoch", "action", "expectation", "program", "accounting", "scope", "credit", "rate", "start", "latest-start", "duration", "lease", "sequence", "ended"} {
		t.Run(mode, func(t *testing.T) {
			var x custodydb.PolicyObservationSession
			if err := json.Unmarshal(raw, &x); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "grant":
				x.GrantID = x.ID
			case "acceptance":
				x.AcceptanceID = x.ID
			case "capture":
				x.CaptureID = x.ID
			case "attempt":
				x.AttemptID = x.ID
			case "session":
				x.ID = x.GrantID
			case "fence":
				x.Fence = x.ID
			case "pod":
				x.PodUid = "replacement"
			case "node":
				x.NodeUid = "replacement"
			case "boot":
				x.BootID = "replacement"
			case "collector":
				x.CollectorPodUid = "replacement"
			case "epoch":
				x.CollectorEpoch = "replacement"
			case "action":
				x.ActionID = "replacement"
			case "expectation":
				x.ExpectationDigest[0]++
			case "program":
				x.ProgramDigest[0]++
			case "accounting":
				x.AccountingRule[0]++
			case "scope":
				x.BindingScope[0]++
			case "credit":
				x.Credit++
			case "rate":
				x.MaxBytesPerSecond++
			case "start":
				x.StartedAt = ts(x.StartedAt.Time.Add(time.Second))
			case "latest-start":
				x.StartBy = ts(x.StartBy.Time.Add(time.Second))
			case "duration":
				x.DurationMillis++
			case "lease":
				x.LeaseUntil = ts(x.LeaseUntil.Time.Add(time.Second))
			case "sequence":
				x.Sequence++
			case "ended":
				x.EndedAt = ts(x.StartedAt.Time.Add(time.Second))
			}
			p, err := policyObservationPermit(x)
			if err == nil || p != (collector.ObservationPermit{}) {
				t.Fatalf("changed original tuple issued a permit: %+v %v", p, err)
			}
		})
	}
}

func TestPolicyObservationPermitDeclinesMalformedFiniteFit(t *testing.T) {
	for _, mode := range []string{"no-dispatch-slack", "beyond-existing-start", "duration-does-not-fit", "lease-over-twenty", "different-lease", "long-action", "unreviewed-rule"} {
		t.Run(mode, func(t *testing.T) {
			x := policyObservationRowFixture()
			switch mode {
			case "no-dispatch-slack":
				x.StartBy = x.StartedAt
			case "beyond-existing-start":
				x.StartBy = ts(x.StartedAt.Time.Add(11 * time.Second))
				x.DurationMillis = 1000
			case "duration-does-not-fit":
				x.StartBy = ts(x.StartBy.Time.Add(time.Millisecond))
			case "lease-over-twenty":
				x.SessionUntil = ts(x.StartedAt.Time.Add(21 * time.Second))
				x.LeaseUntil = x.SessionUntil
			case "different-lease":
				x.LeaseUntil = ts(x.SessionUntil.Time.Add(-time.Second))
			case "long-action":
				x.DurationMillis = 16000
			case "unreviewed-rule":
				x.AccountingRule[0]++
			}
			x.BindingScope = policyObservationScope(x)
			if p, err := policyObservationPermit(x); err == nil || p != (collector.ObservationPermit{}) {
				t.Fatalf("malformed session accepted: %+v %v", p, err)
			}
		})
	}
}

func TestPolicyObservationSourceKeepsSameResolvedPodAndOriginalInterval(t *testing.T) {
	now := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	for _, mode := range []string{"exact", "foreign-pod", "replacement-pin", "source-before-pod", "source-after-pod-end", "future", "elapsed"} {
		t.Run(mode, func(t *testing.T) {
			var c app.APIExecutionCheck
			c.Work.Accepted.Expectation.PodUID = "workload-pod"
			c.Plan.Input.Target.Pin.UID = "workload-pod"
			c.Plan.Input.Target.ObservedAt = now.Add(-time.Second)
			c.Plan.Input.Target.FreshUntil = now.Add(4 * time.Second)
			source := targets.PacketSourceObservation{PodUID: "workload-pod", NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "process", ObservedAt: now, FreshUntil: now.Add(3 * time.Second)}
			switch mode {
			case "foreign-pod":
				source.PodUID = "other"
			case "replacement-pin":
				c.Plan.Input.Target.Pin.UID = "other"
			case "source-before-pod":
				source.ObservedAt = now.Add(-2 * time.Second)
			case "source-after-pod-end":
				source.FreshUntil = now.Add(5 * time.Second)
			case "future":
				source.ObservedAt = now.Add(time.Second)
			case "elapsed":
				source.FreshUntil = now
			}
			if got := policyObservationSourceCurrent(source, c, now); got != (mode == "exact") {
				t.Fatalf("source admission=%v mode=%s", got, mode)
			}
		})
	}
}

func TestPolicyObservationProgramMatchesActualNodeDigest(t *testing.T) {
	program := []artifact.FilterInstruction{{Code: 0x28, Jt: 1, Jf: 2, K: 0xabcdef01}, {Code: 6, K: 65535}}
	node := []planvalue.BPFInstruction{{Code: 0x28, Jt: 1, Jf: 2, K: 0xabcdef01}, {Code: 6, K: 65535}}
	expected := planning.FilterProgramDigest(node)
	got := policyObservationProgramDigest(program)
	if !bytes.Equal(got, expected[:]) {
		t.Fatalf("observation program digest %x differs from actual node cBPF digest %x", got, expected)
	}
	program[0].Jf++
	if bytes.Equal(policyObservationProgramDigest(program), expected[:]) {
		t.Fatal("changed instruction retained program identity")
	}
}
