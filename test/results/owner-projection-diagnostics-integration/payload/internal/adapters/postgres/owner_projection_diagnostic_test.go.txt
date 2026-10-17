package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

func TestOwnerProjectionSQLDiagnosticKeepsClosedStagesAndOriginalCause(t *testing.T) {
	private := errors.New("synthetic-private-sql-connection-password")
	seen := map[string]bool{}
	for check := ownerProjectionSQLEntry; check <= ownerProjectionSQLResult; check++ {
		e := &OwnerProjectionSQLFailure{check: check, cause: private}
		if !errors.Is(e, private) || e.Check() != check || strings.Contains(e.Error(), private.Error()) || check.String() == "unknown" || seen[check.String()] {
			t.Fatal("changed SQL error identity or unsafe check", check, e)
		}
		seen[check.String()] = true
	}
	if OwnerProjectionSQLCheck(255).String() != "unknown" {
		t.Fatal("unknown check rendered arbitrary value")
	}
}

func TestOwnerProjectionSQLDiagnosticActualEntryPreservesNormalization(t *testing.T) {
	for _, s := range []*OwnerIdentityOperationSQL{nil, {}} {
		out, err := s.AdvanceOwnerProjectionOperation(context.Background(), nil)
		var failure *OwnerProjectionSQLFailure
		if !errors.Is(err, cfg.ErrUnavailable) || !errors.As(err, &failure) || failure.Check() != ownerProjectionSQLEntry || out.Status != "" {
			t.Fatal("actual empty admission diagnostic changed original refusal", out, err)
		}
	}
}
