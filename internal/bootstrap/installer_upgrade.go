package bootstrap

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
)

// RunInstallerUpgrade applies this release's missing migrations to an
// installed database as the operator's schema-owning DDL role (ADR-227). The
// inputs directory holds postgres-endpoint.json (the installation's
// PostgreSQL endpoint) and postgres-ddl.json (the DDL credential); ambient PG*
// variables are refused as for every other SQL credential.
func RunInstallerUpgrade(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("installer-upgrade", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputs := flags.String("inputs", "", "directory with postgres-endpoint.json and postgres-ddl.json")
	if err := flags.Parse(args); err != nil || *inputs == "" || flags.NArg() != 0 {
		return mounts.ErrUnavailable
	}
	files, err := os.OpenRoot(*inputs)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer files.Close()
	raw, err := files.ReadFile("postgres-endpoint.json")
	if err != nil {
		return mounts.ErrUnavailable
	}
	var endpoint contracts.OwnerPostgresEndpoint
	if json.Unmarshal(raw, &endpoint) != nil || endpoint.Host == "" || endpoint.Port < 1 || endpoint.Database == "" || len(endpoint.Roots) == 0 {
		return mounts.ErrUnavailable
	}
	if endpoint.MaxConnections < 1 {
		endpoint.MaxConnections = 1
	}
	call, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	in := &providerInputs{files: files, postgresEndpoint: endpoint}
	c, err := in.sqlConfig(call, "postgres-ddl.json")
	if err != nil {
		return err
	}
	upgrade, err := postgres.NewUpgradeSchema(c.ConnConfig)
	if err != nil {
		return err
	}
	defer upgrade.Close()
	from, to, err := upgrade.Run(call)
	if err != nil {
		// A failed step leaves the earlier steps applied; a rerun resumes.
		_, _ = fmt.Fprintf(out, "schema upgrade stopped at %d (started at %d); rerun to resume\n", to, from)
		return err
	}
	if from == to {
		_, err = fmt.Fprintf(out, "schema already at %d\n", to)
	} else {
		_, err = fmt.Fprintf(out, "schema upgraded from %d to %d\n", from, to)
	}
	return err
}
