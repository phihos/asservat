package kubernetes

import (
	"testing"
	"time"
)

func TestInitialPreparationTerminalObservationPrecision(t *testing.T) {
	launch := time.Date(2026, 10, 12, 12, 0, 1, 900000000, time.UTC)
	now := launch.Add(3 * time.Second)
	for _, v := range []struct {
		name              string
		started, finished time.Time
		want              bool
	}{
		{"same-second", launch.Truncate(time.Second), now.Truncate(time.Second), true},
		{"prior-second", launch.Truncate(time.Second).Add(-time.Second), now.Truncate(time.Second), false},
		{"future-finished", launch.Truncate(time.Second), now.Truncate(time.Second).Add(time.Second), false},
		{"reversed", now.Truncate(time.Second), launch.Truncate(time.Second), false},
		{"missing", time.Time{}, now.Truncate(time.Second), false},
	} {
		t.Run(v.name, func(t *testing.T) {
			if got := initialPreparationTerminalTimes(v.started, v.finished, launch, now); got != v.want {
				t.Fatalf("observational ordering=%t want=%t", got, v.want)
			}
		})
	}
	if launch.Nanosecond() != 900000000 || !initialHandoverInterval(launch, launch.Add(5*time.Second)) || initialHandoverInterval(launch, launch.Add(5*time.Second+time.Microsecond)) {
		t.Fatal("observation changed authority precision")
	}
}
