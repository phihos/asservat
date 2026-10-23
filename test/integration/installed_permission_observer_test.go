package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// This fixture reads current installed authority with the same scoped SQL
// credential as the hub. The administrator supplies only its private fixture
// endpoint; it is never passed to a runtime ledger or used to author a result.
func installedPermissionObserver(t *testing.T, ctx context.Context, admin *pgxpool.Pool, api kubernetes.Interface, namespace, installation, root string) (*postgres.Permissions, func()) {
	t.Helper()
	projection, err := api.CoreV1().Secrets(namespace).Get(ctx, contracts.PublicRuntimeProjectionName(installation), meta.GetOptions{})
	if err != nil {
		t.Fatal("installed permission projection", err)
	}
	raw := projection.Data["sql-public-hub-runtime.json"]
	var login contracts.OwnerSQLCredential
	if json.Unmarshal(raw, &login) != nil || login.Username == "" || login.Password == "" {
		t.Fatal("installed hub metadata login missing")
	}
	defer clear(raw)
	c := admin.Config().ConnConfig
	address, tlsConfig := pgTLSBridge(t, net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port))))
	dsn := url.URL{Scheme: "postgres", User: url.UserPassword(login.Username, login.Password), Host: address, Path: "/" + c.Database, RawQuery: "sslmode=disable"}
	pc, err := pgxpool.ParseConfig(dsn.String())
	if err != nil {
		t.Fatal("installed permission pool configuration")
	}
	pc.ConnConfig.TLSConfig, pc.ConnConfig.Fallbacks, pc.MaxConns = tlsConfig, nil, 1
	reader, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal("installed permission pool")
	}
	retained := false
	defer func() {
		if !retained {
			reader.Close()
		}
	}()
	permissions, err := postgres.NewPermissions(ctx, reader, root)
	if err != nil {
		t.Fatal("installed permission observer", err)
	}
	// The shared hub still cannot accept or suspend permission projections; that
	// remains a separate worker responsibility.
	_, err = reader.Exec(ctx, "UPDATE permission_stream SET suspended=suspended WHERE false")
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "42501" {
		t.Fatal("installed permission reader did not establish SQL privilege denial")
	}
	retained = true
	return permissions, reader.Close
}

// Actual PostgreSQL role/TLS checks, with a synthetic projected Secret only.
// This does not qualify installed projection protection or accepted Deny state.
func TestInstalledPermissionObserverWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run the owned custody fixture with this exact test")
	}
	raw, err := os.ReadFile(path)
	var fixture struct{ Postgres string }
	if err != nil || json.Unmarshal(raw, &fixture) != nil || fixture.Postgres == "" {
		t.Fatal("fixture unavailable")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, fixture.Postgres)
	if err != nil {
		t.Fatal("fixture administrator")
	}
	defer admin.Close()
	const role = "installed_permission_probe"
	const password = "synthetic-permission-observer"
	if _, err = admin.Exec(ctx, "CREATE ROLE installed_permission_probe LOGIN PASSWORD 'synthetic-permission-observer'; GRANT USAGE ON SCHEMA public TO installed_permission_probe; GRANT SELECT ON goose_db_version,permission_stream,permission_basis,permission_assignment,authority_audit TO installed_permission_probe; GRANT UPDATE(id) ON permission_stream TO installed_permission_probe"); err != nil {
		t.Fatal("synthetic scoped role", err)
	}
	root, installation := custodyID(), custodyID()
	if _, err = postgres.NewPermissions(ctx, admin, root); err == nil {
		t.Fatal("plaintext administrator became a runtime permission observer")
	}
	c := admin.Config().ConnConfig
	address, roots := pgTLSBridge(t, net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port))))
	dsn := url.URL{Scheme: "postgres", User: url.UserPassword(c.User, c.Password), Host: address, Path: "/" + c.Database, RawQuery: "sslmode=disable"}
	pc, err := pgxpool.ParseConfig(dsn.String())
	if err != nil {
		t.Fatal("administrator test configuration")
	}
	pc.ConnConfig.TLSConfig, pc.ConnConfig.Fallbacks, pc.MaxConns = roots, nil, 1
	unsafe, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal("administrator test pool")
	}
	_, rejected := postgres.NewPermissions(ctx, unsafe, root)
	unsafe.Close()
	if rejected == nil {
		t.Fatal("verified TLS alone allowed administrator runtime authority")
	}
	credential, err := json.Marshal(contracts.OwnerSQLCredential{Username: role, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	api := fake.NewSimpleClientset(&core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "installed-observer", Name: contracts.PublicRuntimeProjectionName(installation)}, Data: map[string][]byte{"sql-public-hub-runtime.json": credential}})
	observer, closeObserver := installedPermissionObserver(t, ctx, admin, api, "installed-observer", installation, root)
	if observer == nil {
		t.Fatal("scoped TLS observer missing")
	}
	closeObserver()
	for {
		var active int
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE usename=$1", role).Scan(&active); err != nil {
			t.Fatal("observer cleanup", err)
		}
		if active == 0 {
			break
		}
		if err = installedJourneyPause(ctx, 10*time.Millisecond); err != nil {
			t.Fatal("scoped observer pool retained a connection")
		}
	}
	t.Log("plaintext and TLS administrator pools rejected; scoped permission-read observer constructed, authority mutation denied and its pool closed")
}
