package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestInitialSQLHistoryDiagnosticHidesValues(t *testing.T) {
	cause := errors.New("synthetic-password SQL and provider details must remain private")
	v := initialSQLHistoryFailure{phase: "creator-membership-retirement", sqlState: "42501", cause: cause}
	got := InitialSQLHistoryDiagnostic(v)
	if got != "history_phase=creator-membership-retirement sqlstate=42501 expired=false" || strings.Contains(v.Error(), "synthetic") || !errors.Is(v, cause) {
		t.Fatal("unsafe diagnostic")
	}
	for _, bad := range []string{"password", "42501 extra", "42p01", "\n4250"} {
		v.sqlState = bad
		if strings.Contains(InitialSQLHistoryDiagnostic(v), bad) {
			t.Fatal("unvalidated SQLSTATE rendered")
		}
	}
	v.phase = "arbitrary-sensitive-input"
	if InitialSQLHistoryDiagnostic(v) != "" || InitialSQLHistoryDiagnostic(cause) != "" {
		t.Fatal("unqualified error rendered")
	}
	if initialHistorySQLState(&pgconn.PgError{Code: "42501", Message: cause.Error()}) != "42501" || initialHistorySQLState(cause) != "" {
		t.Fatal("incorrect safe SQLSTATE extraction")
	}
}
