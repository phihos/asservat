package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RunSchemaWait is the init container of SQL-using Deployments (Helm-native
// installation, startup order): it returns once the database schema is at
// least the version this binary was compiled for. The config file supplies
// only its `postgres` endpoint; the credential and CA are mounted files.
func RunSchemaWait(ctx context.Context, args []string, log io.Writer) error {
	flags := flag.NewFlagSet("schema-wait", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	config := flags.String("config", contracts.HubAPIConfigRoot+"/"+contracts.HubAPIConfigFile, "component config with a postgres section")
	credential := flags.String("credential", contracts.OwnerDeploymentRoot+"/sql-owner-runtime.json", "SQL credential file")
	ca := flags.String("ca", contracts.OwnerDeploymentRoot+"/"+contracts.HubAPIPostgresCAFile, "PostgreSQL CA bundle")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || filepath.Dir(*credential) != filepath.Dir(*ca) {
		return fmt.Errorf("schema-wait: usage: schema-wait [--config file] [--credential file] [--ca file] (credential and CA in one directory)")
	}
	raw, err := os.ReadFile(*config)
	if err != nil {
		return fmt.Errorf("schema-wait: config unreadable")
	}
	var c struct {
		Postgres contracts.HubAPIPostgres `json:"postgres"`
	}
	if json.NewDecoder(bytes.NewReader(raw)).Decode(&c) != nil || c.Postgres.Host == "" {
		return fmt.Errorf("schema-wait: config has no postgres endpoint")
	}
	files, err := os.OpenRoot(filepath.Dir(*credential))
	if err != nil {
		return fmt.Errorf("schema-wait: credential directory unreadable")
	}
	defer files.Close()
	last := time.Time{}
	for {
		version, err := schemaVersion(ctx, files, c.Postgres, filepath.Base(*credential), filepath.Base(*ca))
		if err == nil && version >= postgres.CompiledSchemaVersion {
			fmt.Fprintf(log, "schema-wait: schema %d is current (binary %d)\n", version, postgres.CompiledSchemaVersion)
			return nil
		}
		if time.Since(last) > 30*time.Second {
			last = time.Now()
			if err != nil {
				fmt.Fprintf(log, "schema-wait: database not ready: %v\n", err)
			} else {
				fmt.Fprintf(log, "schema-wait: schema %d, waiting for %d\n", version, postgres.CompiledSchemaVersion)
			}
		}
		if !sleepContext(ctx, 2*time.Second) {
			return ctx.Err()
		}
	}
}

func schemaVersion(ctx context.Context, files *os.Root, p contracts.HubAPIPostgres, credential, ca string) (int64, error) {
	roots, err := readCA(ctx, files, ca, time.Now())
	if err != nil {
		return 0, err
	}
	in := &providerInputs{files: files, postgresEndpoint: contracts.OwnerPostgresEndpoint{Host: p.Host, Port: p.Port, Database: p.Database, Roots: roots, MaxConnections: 1}}
	config, err := in.sqlConfig(ctx, credential)
	if err != nil {
		return 0, err
	}
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	pool, err := pgxpool.NewWithConfig(call, config)
	if err != nil {
		return 0, mounts.ErrUnavailable
	}
	defer pool.Close()
	var version int64
	err = pool.QueryRow(call, `SELECT COALESCE(max(version_id),0) FROM goose_db_version WHERE is_applied`).Scan(&version)
	return version, err
}
