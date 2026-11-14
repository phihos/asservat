package integration

import (
	"os"
)

// Development-only fast focus loop (docs/development-workflow.md). Keep mode
// leaves one fresh installation running after its focus and records what a
// later focus needs; rerun mode runs only that focus against it. Neither is a
// qualification: the harness marks their reports "qualification": false and
// refuses both under CI. Product checks and assertions are unchanged; the
// rerun only gives each run its own idempotency keys and synthetic source
// names, which an ordinary run never repeats.

func installedKeepMode() bool { return os.Getenv("ASSERVAT_INSTALLED_KEEP") == "1" }

// installedKeptRuns is how many focus runs the operator's synthetic capacity
// funds: the keep run plus the reruns the harness allows (KEPT_INSTALLED_RUNS).
// An ordinary run funds exactly its one focus, unchanged.
func installedKeptRuns() int64 {
	if installedKeepMode() {
		return 4 // the system byte reserve (8 GiB) fits four
	}
	return 1
}
