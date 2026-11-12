package bootstrap

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestInitialOpenBaoRemedyNamesOnlyClosedStages(t *testing.T) {
	const secret = "synthetic-private-token-and-url"
	for _, stage := range []string{"source", "login", "ready", "mint-original-claim", "mint-response", "mint-verification/issuer-profile"} {
		err := fmt.Errorf("%s: %w", secret, initialOpenBaoCheck(stage))
		got := InitialPreparationRemedy(err)
		if !strings.Contains(got, "stopped at "+stage+":") || strings.Contains(got, secret) {
			t.Fatalf("closed stage missing or private cause exposed: %q", got)
		}
	}
	for _, err := range []error{errors.New(secret), initialOpenBaoCheck(secret), initialOpenBaoCheck("mint-verification/" + secret)} {
		if got := InitialPreparationRemedy(err); strings.Contains(got, secret) || strings.Contains(got, "stopped at") {
			t.Fatal("arbitrary error entered stage diagnostic")
		}
	}
}
