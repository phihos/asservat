package providerconfig

import (
	"fmt"
	"testing"
)

func TestInitialIssuerAcceptsOnlyExactIntentionalCapNotice(t *testing.T) {
	notice := func(seconds int64) string {
		return fmt.Sprintf("Explicit max TTL specified both during creation call and in role; using the lesser value of %d seconds", seconds)
	}
	for _, warnings := range [][]string{nil, {notice(283)}} {
		if !InitialIssuerWarningsAllowed(warnings, 283) {
			t.Fatal("exact intended request-cap notice refused")
		}
	}
	for _, warnings := range [][]string{{notice(282)}, {notice(284)}, {notice(900)}, {notice(283), notice(283)}, {notice(283), "Policy does not exist"}, {"Policy does not exist"}, {notice(283) + " changed"}, {""}} {
		if InitialIssuerWarningsAllowed(warnings, 283) {
			t.Fatal("changed or additional provider warning accepted")
		}
	}
	for _, seconds := range []int64{-1, 0, 901} {
		if InitialIssuerWarningsAllowed(nil, seconds) || InitialIssuerWarningsAllowed([]string{notice(seconds)}, seconds) {
			t.Fatal("invalid original cap accepted")
		}
	}
}
