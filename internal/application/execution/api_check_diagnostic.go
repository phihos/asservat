package execution

import "time"

// apiCheckStep distinguishes the fixed current-check boundary without reading
// provider text or trusting a dependency's diagnostic labels. Its original
// error remains available through errors.Is/As; no authority result changes.
type apiCheckStep struct {
	step string
	err  error
}

func (e apiCheckStep) Error() string     { return "api context check " + e.step }
func (e apiCheckStep) Unwrap() error     { return e.err }
func (e apiCheckStep) FixedStep() string { return e.step }

// limit names the earliest input of the check's interval and its remaining
// bucket, for the refusal line of a failed preparation. It reads only the
// check's own dates; it neither renews nor reorders any bound.
func (c APIExecutionCheck) limit(original, now time.Time) string {
	in := c.Plan.Input
	name, until := "original", original
	for _, b := range []struct {
		name string
		at   time.Time
	}{{"interval", c.CheckedAt.Add(5 * time.Second)}, {"target", in.Target.FreshUntil}, {"capability", in.Capability.FreshUntil}, {"retention", in.Retention.ValidUntil}, {"deadline", in.Deadline}, {"eligibility", c.Eligibility.ValidUntil}, {"recovery", c.Recovery.FreshUntil}, {"process", c.Process.ValidUntil}, {"write", c.Work.Accepted.Expectation.Registration.WriteUntil}} {
		if !b.at.IsZero() && b.at.Before(until) {
			name, until = b.name, b.at
		}
	}
	switch left := until.Sub(now); {
	case left <= 0:
		return name + "@0"
	case left < 500*time.Millisecond:
		return name + "@<0.5s"
	case left < time.Second:
		return name + "@<1s"
	case left < 2*time.Second:
		return name + "@<2s"
	}
	return name + "@>=2s"
}
