package bootstrap

import (
	cfg "asservat.local/asservat/internal/domain/configuration"
	"errors"
	"strings"
	"testing"
)

func TestInitialPreparerRemedyKeepsOriginalPlanAndHidesRawErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{{cfg.ErrChanged, "requalify"}, {cfg.ErrDenied, "preparation credential"}, {cfg.ErrInvalid, "without replacing"}, {errors.New("synthetic sensitive provider response"), "same Helm release and plan"}} {
		got := InitialPreparationRemedy(tc.err)
		if !strings.Contains(got, tc.want) || strings.Contains(got, "sensitive provider response") {
			t.Fatalf("unsafe or unhelpful remedy: %s", got)
		}
	}
}

func TestInitialPreparerZeroValueCannotRun(t *testing.T) {
	var d InitialPreparationDeployment
	if _, err := d.Run(); err == nil {
		t.Fatal("zero-value preparer accepted")
	}
	d.Close()
}
