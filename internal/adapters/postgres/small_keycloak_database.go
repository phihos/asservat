package postgres

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

// SmallKeycloakDatabasePresence is a finite, read-only initialization check,
// not an activation/recovery authority or a reusable database observation.
type SmallKeycloakDatabasePresence struct{ config *pgx.ConnConfig }

var smallKeycloakDatabaseHost = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

// NewSmallKeycloakDatabasePresence accepts independently mounted operator
// credentials and public roots. Its SQL session is separate from Keycloak's
// five runtime connections; pgx may additionally open one cancellation socket
// on failure. It never parses a credential-bearing DSN.
func NewSmallKeycloakDatabasePresence(p contracts.OwnerPostgresEndpoint, credential contracts.OwnerSQLCredential) (*SmallKeycloakDatabasePresence, error) {
	if (net.ParseIP(p.Host) == nil && !smallKeycloakDatabaseHost.MatchString(p.Host)) || p.Port < 1 || p.Port > 65535 || !identity.Text(p.Database, 63) || p.MaxConnections != 1 || !identity.Text(credential.Username, 63) || len(credential.Password) < 1 || len(credential.Password) > 4096 || strings.ContainsRune(credential.Password, 0) {
		return nil, cfg.ErrInvalid
	}
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "PG") {
			return nil, cfg.ErrInvalid
		}
	}
	roots, _, err := mtls.OwnerTrustRoots(p.Roots, time.Now())
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	c, err := pgx.ParseConfig("host=localhost port=1 user=unused password=unused dbname=unused sslmode=disable")
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	c.Host, c.Port, c.Database = p.Host, uint16(p.Port), p.Database
	c.User, c.Password = credential.Username, credential.Password
	c.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, ServerName: p.Host, RootCAs: roots}
	c.Fallbacks = nil
	c.Tracer = nil
	c.ValidateConnect, c.AfterConnect = nil, nil
	c.ConnectTimeout = 5 * time.Second
	c.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	c.RuntimeParams = map[string]string{"application_name": "asservat-keycloak-empty-check", "search_path": "pg_catalog", "timezone": "UTC", "default_transaction_read_only": "on", "statement_timeout": "5000ms", "lock_timeout": "1000ms", "idle_in_transaction_session_timeout": "5000ms"}
	return &SmallKeycloakDatabasePresence{config: c}, nil
}

// The schema dependency check includes all namespace-owned object kinds,
// including functions, types, views, sequences and operators, rather than only
// known Keycloak tables. The remaining checks cover non-schema state. The
// standard public schema and PostgreSQL's built-in plpgsql extension are empty
// database defaults, not retained application state.
const smallKeycloakDatabasePresenceSQL = `SELECT
 current_database()=$1 AND session_user=$2 AND current_user=$2
 AND current_setting('default_transaction_read_only')='on',
 EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname NOT IN ('public','information_schema') AND n.nspname !~ '^pg_')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_namespace n ON n.oid=d.refobjid WHERE d.refclassid='pg_catalog.pg_namespace'::regclass AND n.nspname NOT IN ('information_schema') AND n.nspname !~ '^pg_')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_extension WHERE extname<>'plpgsql')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_largeobject_metadata)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_event_trigger)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_foreign_server)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_foreign_data_wrapper)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_publication)`

// Exists returns false only after this call positively observes an empty exact
// database under verified TLS. Errors and cancellation cannot initialize state.
func (s *SmallKeycloakDatabasePresence) Exists(ctx context.Context) (bool, error) {
	if s == nil || s.config == nil || ctx == nil || ctx.Err() != nil {
		return false, cfg.ErrUnavailable
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	conn, err := pgx.ConnectConfig(ctx, s.config.Copy())
	if err != nil {
		return false, cfg.ErrUnavailable
	}
	defer conn.Close(ctx)
	var same, present bool
	err = conn.QueryRow(ctx, smallKeycloakDatabasePresenceSQL, s.config.Database, s.config.User).Scan(&same, &present)
	if err != nil || !same || ctx.Err() != nil {
		return false, cfg.ErrUnavailable
	}
	return present, nil
}
