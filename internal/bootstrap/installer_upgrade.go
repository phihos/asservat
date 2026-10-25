package bootstrap

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"k8s.io/client-go/rest"
)

// RunInstallerUpgrade applies this release's missing migrations to an
// installed database as the operator's schema-owning DDL role (ADR-227). The
// inputs directory holds postgres-endpoint.json (the installation's
// PostgreSQL endpoint) and postgres-ddl.json (the DDL credential); ambient PG*
// variables are refused as for every other SQL credential.
//
// With --image (and --namespace, --installation) it is the phase-2 image
// change, run as the installer runner account in a Pod of that image: it
// migrates (an upgrade) or checks the schema floor (a rollback to an image in
// the release history), advances the release record and rolls hub-worker and
// hub-api out to the image.
func RunInstallerUpgrade(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("installer-upgrade", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputs := flags.String("inputs", "", "directory with postgres-endpoint.json and postgres-ddl.json")
	image := flags.String("image", "", "the release image (repo@sha256:...) hub-api and hub-worker change to; this Pod's own image")
	namespace := flags.String("namespace", "", "with --image: the hub namespace")
	installation := flags.String("installation", "", "with --image: the installation ID")
	if err := flags.Parse(args); err != nil || *inputs == "" || flags.NArg() != 0 {
		return mounts.ErrUnavailable
	}
	if (*image != "") != (*namespace != "") || (*image != "") != (*installation != "") || (*image != "" && (!contracts.ReleaseImageValid(*image) || !authorization.UUID(*installation))) {
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
	var config *rest.Config
	if *image != "" {
		// The runner's own in-cluster account; the binary must be the image
		// it changes to, so the compiled schema is that release's.
		if config, err = rest.InClusterConfig(); err != nil {
			return mounts.ErrUnavailable
		}
		if err = kube.VerifyOwnPodImage(ctx, config, os.Getenv(contracts.InstallerUpgradePodNamespaceEnvironment), os.Getenv(contracts.InstallerUpgradePodNameEnvironment), *image); err != nil {
			return err
		}
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
	if *image != "" {
		return releaseChange{config: config, namespace: *namespace, installation: *installation, image: *image, compiled: postgres.CompiledSchemaVersion, schema: upgrade, out: out, poll: 2 * time.Second, settle: 5 * time.Minute, stable: 20 * time.Second}.run(call)
	}
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
