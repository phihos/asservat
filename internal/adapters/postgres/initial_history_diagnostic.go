package postgres

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// Only compiler-selected stages, a validated SQLSTATE and cancellation state
// leave this boundary. Provider errors can contain credentials or SQL text.
type initialSQLHistoryFailure struct {
	phase, sqlState string
	expired         bool
	cause           error
}

func (e initialSQLHistoryFailure) Error() string { return "initial SQL history unavailable" }
func (e initialSQLHistoryFailure) Unwrap() error { return e.cause }
func initialHistorySQLState(e error) string {
	var p *pgconn.PgError
	if !errors.As(e, &p) || !validInitialHistorySQLState(p.Code) {
		return ""
	}
	return p.Code
}
func validInitialHistorySQLState(s string) bool {
	if len(s) != 5 {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= '0' && b <= '9' || b >= 'A' && b <= 'Z') {
			return false
		}
	}
	return true
}
func InitialSQLHistoryDiagnostic(e error) string {
	var h initialSQLHistoryFailure
	if !errors.As(e, &h) {
		return ""
	}
	switch h.phase {
	case "inputs", "password-verifier", "transaction", "original-interval", "original-roles", "history-role-lookup", "pristine-history", "history-role-create", "history-role-grants", "creator-identity", "creator-membership-retirement", "history-role-privileges", "final-original-interval", "password-authentication", "password-ping":
	default:
		return ""
	}
	code := "none"
	if validInitialHistorySQLState(h.sqlState) {
		code = h.sqlState
	}
	return fmt.Sprintf("history_phase=%s sqlstate=%s expired=%t", h.phase, code, h.expired)
}
