package integration

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNativePacingOptionalCPUAvailabilityNeverBecomesZero(t *testing.T) {
	now := time.Now()
	sample := nativeTrafficCPU{StartedAt: now, FinishedAt: now.Add(time.Millisecond), ContainerID: "same-owned", Quota: 10000, Period: 100000, Counters: map[string]uint64{"usage_usec": 100, "user_usec": 60, "system_usec": 40, "nr_periods": 5, "nr_throttled": 2, "throttled_usec": 7}}
	for _, mode := range []string{"complete", "both-missing", "before-missing", "after-missing", "changed-container", "backward", "overlap"} {
		t.Run(mode, func(t *testing.T) {
			before, after := sample, sample
			after.StartedAt = now.Add(time.Second)
			after.FinishedAt = after.StartedAt.Add(time.Millisecond)
			after.Counters = map[string]uint64{}
			for k, v := range sample.Counters {
				after.Counters[k] = v + 1
			}
			a, b := &before, &after
			switch mode {
			case "both-missing":
				a, b = nil, nil
			case "before-missing":
				a = nil
			case "after-missing":
				b = nil
			case "changed-container":
				after.ContainerID = "replacement"
			case "backward":
				after.Counters["usage_usec"] = 99
			case "overlap":
				after.StartedAt = before.StartedAt
			}
			got := nativePacingTargetCPUSamples(a, b)
			if got.BeforeAvailable != (a != nil) || got.AfterAvailable != (b != nil) || got.DeltaAvailable != (mode == "complete") {
				t.Fatal("diagnostic availability", got)
			}
			if mode == "complete" {
				if got.Delta["usage_usec"] != 1 {
					t.Fatal(got)
				}
			} else if got.Delta != nil {
				t.Fatal("missing diagnostic invented zero delta", got)
			}
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var persisted map[string]json.RawMessage
			if json.Unmarshal(raw, &persisted) != nil {
				t.Fatal("CPU report malformed")
			}
			if mode != "complete" && string(persisted["Delta"]) != "null" {
				t.Fatal("unavailable diagnostic serialized as measured zero", string(raw))
			}
		})
	}
}
