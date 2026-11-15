package integration

import (
	"os"
	"strings"
)

// Several installed focuses in one run (ASSERVAT_JOURNEY_FOCUS=a,b,c): one
// bootstrap, then each focus in sequence as its own subtest of
// installer-continuation, on the same installation. Every focus keeps its own
// checks; only the bootstrap is shared, so the listed focuses must configure
// the same bootstrap (installedFocusBootstrapSignature). The capacity and
// identity budgets that each focus sizes for itself add up, so no focus runs
// on what an earlier one left of its budget. A later focus does not start
// after a failure: the installation may hold the failed focus' state.

// installedJourneyFoci is ASSERVAT_JOURNEY_FOCUS in run order.
func installedJourneyFoci() []string {
	value := os.Getenv("ASSERVAT_JOURNEY_FOCUS")
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

// installedFocusCurrent is the focus whose subtest is running (or which
// installedEachFocus evaluates); empty otherwise.
var installedFocusCurrent string

// installedEachFocus calls fn once per listed focus with that focus current
// (once with the single focus otherwise).
func installedEachFocus(fn func()) {
	foci := installedJourneyFoci()
	if len(foci) <= 1 {
		fn()
		return
	}
	saved := installedFocusCurrent
	defer func() { installedFocusCurrent = saved }()
	for _, focus := range foci {
		installedFocusCurrent = focus
		fn()
	}
}

// installedAnyFocus reports whether focus is listed.
func installedAnyFocus(focus string) bool {
	return installedAnyFocusMatch(func() bool { return installedJourneyFocus() == focus })
}

// installedAnyFocusMatch reports whether match holds for any listed focus.
func installedAnyFocusMatch(match func() bool) bool {
	any := false
	installedEachFocus(func() { any = any || match() })
	return any
}
