package bootstrap

import (
	"errors"
)

// regionalOutcome is "ok" or the error's fixed step and closed cause.
func regionalOutcome(err error) string {
	return regionalOutcomeClass(err) + observationFailureDetail(err)
}

func regionalOutcomeClass(err error) string {
	if err == nil {
		return "ok"
	}
	var step interface{ FixedStep() string }
	if errors.As(err, &step) {
		return step.FixedStep() + " (" + regionalCause(err) + ")"
	}
	return regionalCause(err)
}
