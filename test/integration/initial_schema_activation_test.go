package integration

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// Fixture diagnostics retain only the standardized code, never SQL text,
// credentials, role names or the provider's message/detail fields.
func initialSchemaCleanupSQLState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && len(pg.Code) == 5 {
		for _, c := range pg.Code {
			if !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'Z') {
				return "unavailable"
			}
		}
		return pg.Code
	}
	return "none"
}
