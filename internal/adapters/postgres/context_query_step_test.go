package postgres

import (
	"errors"
	"testing"

	value "asservat.local/asservat/internal/domain/analysis"
)

func TestQueryRefusalNamesNestedStepAndStaysUnavailable(t *testing.T) {
	err := queryRefusal("admission", queryRefusal("transaction", queryRefusal("fence-permission-fresh", nil)))
	var step interface{ FixedStep() string }
	if !errors.Is(err, value.ErrUnavailable) || !errors.As(err, &step) || step.FixedStep() != "admission/transaction/fence-permission-fresh" {
		t.Fatal(err)
	}
}
