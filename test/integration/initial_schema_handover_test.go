package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The manager is a separately provisioned fixture input. It has no application
// grants: only the actual schema loader may install the compiled grant union.
func initialEmptySchemaManager(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, roots *tls.Config) *pgxpool.Pool {
	t.Helper()
	var empty bool
	if err := admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')`).Scan(&empty); err != nil || !empty {
		t.Fatal("schema qualification requires an actually empty owned database")
	}
	name := "initial_schema_manager_" + strings.ReplaceAll(custodyID(), "-", "")
	until := time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)
	if _, err := admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{name}.Sanitize()+" LOGIN NOINHERIT NOSUPERUSER CREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD 'synthetic-operator' VALID UNTIL '"+until+"'"); err != nil {
		t.Fatal("fixture schema manager unavailable")
	}
	c, err := pgxpool.ParseConfig("postgres://" + name + ":synthetic-operator@" + address + "/custody_test?sslmode=disable")
	if err != nil {
		t.Fatal("fixture manager configuration unavailable")
	}
	c.ConnConfig.TLSConfig = roots.Clone()
	c.ConnConfig.Fallbacks = nil
	c.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		t.Fatal("fixture manager pool unavailable")
	}
	t.Cleanup(pool.Close)
	return pool
}

func initialSchemaHandoverSame(a, b contracts.InitialPreparationSchema) bool {
	x, ex := json.Marshal(a)
	y, ey := json.Marshal(b)
	return ex == nil && ey == nil && bytes.Equal(x, y)
}

// Executes the actual protected loader against Kubernetes and empty SQL. The
// loader runs in the test process; the subsequent activation uses the actual
// product executable in its original Pod. Neither is bootstrap provisioning.
func initialMountedSchemaHandover(t *testing.T, ctx context.Context, admin *pgxpool.Pool, api kubernetes.Interface, c contracts.InitialPreparer, adminToken, probeToken string) contracts.InitialPreparationSchema {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal("schema fixture encoding unavailable")
		}
		defer clear(data)
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal("schema fixture projection unavailable")
		}
	}
	write("deployment.json", c)
	credential := admin.Config().ConnConfig
	write("postgres-ddl.json", contracts.OwnerSQLCredential{Username: credential.User, Password: credential.Password})
	for name, token := range map[string]string{"administrator-token": adminToken, "probe-token": probeToken} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(token), 0600); err != nil {
			t.Fatal("schema fixture token projection unavailable")
		}
	}
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal("schema fixture root unavailable")
	}
	defer files.Close()
	run := func() contracts.InitialPreparationSchema {
		t.Helper()
		d, err := bootstrap.NewInitialSchemaDeployment(ctx, files)
		if err != nil {
			t.Fatal("actual schema loader construction", err)
		}
		defer d.Close()
		if err = d.Run(ctx); err != nil {
			t.Fatal("actual schema loader execution", err)
		}
		cm, err := api.CoreV1().ConfigMaps(c.Plan.BootstrapNamespace.Name).Get(ctx, c.Plan.RootName, meta.GetOptions{})
		if err != nil {
			t.Fatal("original schema root unavailable")
		}
		root, err := contracts.DecodeInitialPreparationRoot(strings.NewReader(cm.Data["root.json"]))
		if err != nil || root.Schema == nil || root.Schema.CompletedAt == nil || len(root.Creates) != 0 || root.Activation != nil {
			t.Fatal("schema loader did not complete before target declaration")
		}
		return *root.Schema
	}
	original := run()
	if again := run(); !initialSchemaHandoverSame(original, again) {
		t.Fatal("completed schema replay replaced its original binding")
	}
	bundle, err := postgres.EmbeddedInitialSchema()
	if err != nil || original.BundleDigest != bundle.Digest || original.Head != bundle.Head || original.Manager != *c.Plan.HistoryManager {
		t.Fatal("schema root does not identify the actual compiled bundle/manager")
	}
	var actualOID uint32
	var actualStart time.Time
	var head int64
	if err = admin.QueryRow(ctx, "SELECT oid,pg_postmaster_start_time() FROM pg_database WHERE datname=current_database()").Scan(&actualOID, &actualStart); err != nil || actualOID != original.DatabaseOID || !actualStart.Equal(original.PostmasterAt) {
		t.Fatal("schema completion does not bind the actual database incarnation")
	}
	if err = admin.QueryRow(ctx, "SELECT max(version_id) FROM public.goose_db_version").Scan(&head); err != nil || head != bundle.Head {
		t.Fatal("actual schema history is incomplete")
	}
	if err = os.Remove(filepath.Join(dir, "postgres-ddl.json")); err != nil {
		t.Fatal("fixture DDL projection removal failed")
	}
	t.Log("actual protected schema loader initialized empty SQL and replayed the original completed bundle; distinct DDL projection removed before preparation")
	return original
}
