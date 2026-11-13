package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

// SetupStepError names the failed setup step and its error class only; it
// never carries provider response bodies or credentials.
type SetupStepError struct {
	Step string
	Err  error
}

func (e *SetupStepError) Error() string {
	return "setup stopped at " + e.Step + " (" + errorClass(e.Err) + ")"
}
func (e *SetupStepError) Unwrap() error { return e.Err }

// setupRetry is how long setup waits for a provider that is not reachable yet.
const setupRetry = 5 * time.Minute

// RunSetup is `asservat setup`: one idempotent Job that prepares the selected
// providers for the Helm-rendered components. With --wait-schema it instead
// waits until the database serves this binary's schema (init containers).
func RunSetup(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || ctx.Err() != nil || out == nil {
		return cfg.ErrUnavailable
	}
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	wait := flags.Bool("wait-schema", false, "wait until the database schema is current, then exit")
	config := flags.String("config", contracts.SetupConfigFile, "configuration with a top-level postgres object")
	credential := flags.String("credential", "", "--wait-schema: one sql-*.json runtime credential")
	ca := flags.String("ca", "", "--wait-schema: PostgreSQL CA bundle (PEM); default: the configuration's postgres roots")
	timeout := flags.Duration("timeout", 15*time.Minute, "overall bound")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *timeout <= 0 || *wait != (*credential != "") || !*wait && *ca != "" {
		return &SetupStepError{"arguments", cfg.ErrInvalid}
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if *wait {
		return waitSchema(ctx, *config, *credential, *ca, out)
	}
	return runSetup(ctx, *config, out)
}

func setupStep(step string, err error) error {
	if err == nil {
		return nil
	}
	return &SetupStepError{step, err}
}

// retryUnavailable repeats f while it reports an unavailable provider, up to
// setupRetry; invalid input, changed state and denials stop at once.
func retryUnavailable(ctx context.Context, f func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, setupRetry)
	defer cancel()
	for {
		err := f(ctx)
		if err == nil || errors.Is(err, cfg.ErrInvalid) || errors.Is(err, cfg.ErrChanged) || errors.Is(err, cfg.ErrDenied) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(2 * time.Second):
		}
	}
}

// setupIDs are the generated installation identities of `<name>-ids`.
type setupIDs struct{ InstallationID, ClusterID, IssuerEpoch string }

func readSetupIDs(dir string) (setupIDs, error) {
	read := func(key string) (string, error) {
		b, err := readSetupFile(filepath.Join(dir, key), 256)
		v := strings.TrimSpace(string(b))
		if err != nil || !authorization.UUID(v) {
			return "", cfg.ErrInvalid
		}
		return v, nil
	}
	var ids setupIDs
	var err error
	for key, dst := range map[string]*string{"installationID": &ids.InstallationID, "clusterID": &ids.ClusterID, "issuerEpoch": &ids.IssuerEpoch} {
		if *dst, err = read(key); err != nil {
			return setupIDs{}, err
		}
	}
	return ids, nil
}

func readSetupFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit || len(b) == 0 {
		return nil, cfg.ErrInvalid
	}
	return b, nil
}

func readSetupCredential(path string) (contracts.OwnerSQLCredential, error) {
	b, err := readSetupFile(path, 16<<10)
	if err != nil {
		return contracts.OwnerSQLCredential{}, err
	}
	defer clear(b)
	c, err := contracts.DecodeOwnerSQLCredential(bytes.NewReader(b))
	if err != nil || c.Username == "" || len(c.Username) > 63 || c.Password == "" {
		return contracts.OwnerSQLCredential{}, cfg.ErrInvalid
	}
	return c, nil
}

func setupRoots(pem []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if len(pem) == 0 || !pool.AppendCertsFromPEM(pem) {
		return nil, cfg.ErrInvalid
	}
	return pool, nil
}

var setupPostgresHost = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

func setupPGConfig(p contracts.SetupPostgres, roots *x509.CertPool, c contracts.OwnerSQLCredential) (*pgx.ConnConfig, error) {
	if !setupPostgresHost.MatchString(p.Host) || p.Port < 1 || p.Port > 65535 || p.Database == "" || len(p.Database) > 63 || roots == nil {
		return nil, cfg.ErrInvalid
	}
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "PG") {
			return nil, cfg.ErrInvalid
		}
	}
	config, err := pgx.ParseConfig("host=localhost port=1 user=unused password=unused dbname=unused sslmode=disable")
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	config.Host, config.Port, config.Database = p.Host, uint16(p.Port), p.Database
	config.User, config.Password = c.Username, c.Password
	config.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, ServerName: p.Host, RootCAs: roots}
	config.Fallbacks = nil
	config.ConnectTimeout = 5 * time.Second
	return config, nil
}

// readRuntimeLogins indexes every mounted `sql-*.json` runtime credential by
// role name. One Secret per component is mounted in its own subdirectory.
func readRuntimeLogins(root string) (map[string]string, error) {
	logins := map[string]string{}
	dirs, err := os.ReadDir(root)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	for _, dir := range dirs {
		if strings.HasPrefix(dir.Name(), ".") {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, dir.Name()))
		if err != nil {
			return nil, cfg.ErrInvalid
		}
		for _, file := range files {
			if !strings.HasPrefix(file.Name(), "sql-") || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}
			c, err := readSetupCredential(filepath.Join(root, dir.Name(), file.Name()))
			if err != nil {
				return nil, err
			}
			if old, ok := logins[c.Username]; ok && old != c.Password {
				return nil, cfg.ErrInvalid
			}
			logins[c.Username] = c.Password
		}
	}
	if len(logins) == 0 {
		return nil, cfg.ErrInvalid
	}
	return logins, nil
}

func validSetupConfiguration(c contracts.SetupConfiguration) bool {
	return c.Format == contracts.SetupFormat && len(validation.IsDNS1123Label(c.Name)) == 0 && len(c.Name) <= 30 &&
		len(validation.IsDNS1123Label(c.Namespace)) == 0 && len(validation.IsDNS1123Subdomain(c.FleetSource)) == 0
}

func runSetup(ctx context.Context, path string, out io.Writer) error {
	raw, err := readSetupFile(path, contracts.SetupMaxBytes)
	if err != nil {
		return setupStep("configuration", err)
	}
	c, err := contracts.DecodeSetupConfiguration(bytes.NewReader(raw))
	if err != nil || !validSetupConfiguration(c) {
		return setupStep("configuration", cfg.ErrInvalid)
	}
	ids, err := readSetupIDs(contracts.SetupIDsRoot)
	if err != nil {
		return setupStep("ids", err)
	}
	if err = setupDatabase(ctx, c, ids, out); err != nil {
		return err
	}
	if c.OpenBao.Bundled {
		if err = setupOpenBao(ctx, c, ids, out); err != nil {
			return err
		}
	}
	if c.ObjectStore.Bundled {
		if err = setupObjectStore(ctx, c, ids, out); err != nil {
			return err
		}
	}
	_, _ = fmt.Fprintln(out, "setup complete")
	return nil
}

func setupDatabase(ctx context.Context, c contracts.SetupConfiguration, ids setupIDs, out io.Writer) error {
	ca, err := readSetupFile(filepath.Join(contracts.SetupPostgresRoot, "ca.crt"), 64<<10)
	if err != nil {
		return setupStep("postgres/ca", err)
	}
	roots, err := setupRoots(ca)
	if err != nil {
		return setupStep("postgres/ca", err)
	}
	admin, err := readSetupCredential(filepath.Join(contracts.SetupPostgresRoot, "administrator.json"))
	if err != nil {
		return setupStep("postgres/administrator", err)
	}
	ddl := admin
	if _, statErr := os.Stat(filepath.Join(contracts.SetupPostgresRoot, "ddl.json")); statErr == nil {
		if ddl, err = readSetupCredential(filepath.Join(contracts.SetupPostgresRoot, "ddl.json")); err != nil {
			return setupStep("postgres/ddl", err)
		}
	}
	adminConfig, err := setupPGConfig(c.Postgres, roots, admin)
	if err != nil {
		return setupStep("postgres/configuration", err)
	}
	ddlConfig, err := setupPGConfig(c.Postgres, roots, ddl)
	if err != nil {
		return setupStep("postgres/configuration", err)
	}
	logins, err := readRuntimeLogins(contracts.SetupSQLRoot)
	if err != nil {
		return setupStep("postgres/runtime-credentials", err)
	}
	// P0: wait for the database before the first effect.
	if err = retryUnavailable(ctx, func(ctx context.Context) error {
		conn, err := pgx.ConnectConfig(ctx, ddlConfig)
		if err != nil {
			return cfg.ErrUnavailable
		}
		return conn.Close(ctx)
	}); err != nil {
		return setupStep("postgres/wait", err)
	}
	_, _ = fmt.Fprintln(out, "postgres reachable")
	// P1: migrations.
	schema, err := postgres.NewUpgradeSchema(ddlConfig)
	if err != nil {
		return setupStep("schema", err)
	}
	from, to, err := schema.Run(ctx)
	_ = schema.Close()
	if err != nil {
		return setupStep("schema", err)
	}
	_, _ = fmt.Fprintf(out, "schema %d -> %d\n", from, to)
	// P2: runtime roles and grants.
	report, err := postgres.EnsureRuntimeRoles(ctx, adminConfig, ids.InstallationID, logins)
	if err != nil {
		var role *postgres.RuntimeRoleError
		if errors.As(err, &role) {
			return setupStep("roles/"+role.Role, err)
		}
		return setupStep("roles", err)
	}
	_, _ = fmt.Fprintf(out, "runtime roles: %d created, %d updated, %d without a mounted credential\n", len(report.Created), len(report.Updated), len(report.Missing))
	for _, name := range report.Missing {
		_, _ = fmt.Fprintln(out, "  no credential mounted: "+name)
	}
	// P3: trust root, activation and first fleet observation.
	kubernetes, err := rest.InClusterConfig()
	if err != nil {
		return setupStep("kubernetes", cfg.ErrUnavailable)
	}
	err = retryUnavailable(ctx, func(ctx context.Context) error {
		a, _, err := kube.ReadSetupFleetSource(ctx, kubernetes, ids.ClusterID, c.Namespace, c.FleetSource, ids.InstallationID)
		if err != nil {
			return setupStep("fleet-source", err)
		}
		if a.IssuerEpoch != ids.IssuerEpoch {
			return setupStep("fleet-source", cfg.ErrChanged)
		}
		return setupStep("seed", postgres.SeedInstallation(ctx, ddlConfig, a))
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, "installation trust seeded")
	return nil
}

func setupOpenBao(ctx context.Context, c contracts.SetupConfiguration, ids setupIDs, out io.Writer) error {
	ca, err := readSetupFile(filepath.Join(contracts.SetupOpenBaoRoot, "ca.crt"), 64<<10)
	if err != nil {
		return setupStep("openbao/ca", err)
	}
	in := providerconfig.OpenBaoSetupInput{Name: c.Name, Namespace: c.Namespace, InstallationID: ids.InstallationID, ClusterID: ids.ClusterID, IssuerEpoch: ids.IssuerEpoch, Accounts: c.OpenBao.Accounts}
	err = retryUnavailable(ctx, func(ctx context.Context) error {
		// The projected token rotates; read it for each attempt.
		token, err := readSetupFile(filepath.Join(contracts.SetupOpenBaoRoot, "token"), 16<<10)
		if err != nil {
			return setupStep("openbao/token", err)
		}
		defer clear(token)
		client, err := providerconfig.SetupOpenBaoLogin(ctx, c.OpenBao.Endpoint, ca, bytes.TrimSpace(token))
		if err != nil {
			return setupStep("openbao/login", err)
		}
		return setupStep("openbao/configure", providerconfig.EnsureOpenBaoSetup(ctx, client, in, out))
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, "openbao configured")
	return nil
}

func setupObjectStore(ctx context.Context, c contracts.SetupConfiguration, ids setupIDs, out io.Writer) error {
	ca, err := readSetupFile(filepath.Join(contracts.SetupObjectStoreRoot, "ca.crt"), 64<<10)
	if err != nil {
		return setupStep("objectstore/ca", err)
	}
	raw, err := readSetupFile(filepath.Join(contracts.SetupObjectStoreRoot, "credentials.json"), 16<<10)
	if err != nil {
		return setupStep("objectstore/credentials", err)
	}
	var admin contracts.SeaweedCredential
	err = json.Unmarshal(raw, &admin)
	clear(raw)
	if err != nil {
		return setupStep("objectstore/credentials", cfg.ErrInvalid)
	}
	// Bucket policies (Deny statements) are compiled with the IAM Secret by
	// `asservat secrets`; the file is optional.
	var policies map[string]json.RawMessage
	if raw, err := readSetupFile(filepath.Join(contracts.SetupObjectStoreRoot, "bucket-policies.json"), 256<<10); err == nil {
		if json.Unmarshal(raw, &policies) != nil {
			return setupStep("objectstore/policies", cfg.ErrInvalid)
		}
	} else if _, statErr := os.Stat(filepath.Join(contracts.SetupObjectStoreRoot, "bucket-policies.json")); statErr == nil {
		return setupStep("objectstore/policies", err)
	}
	buckets := []string{c.ObjectStore.AuditBucket, c.ObjectStore.EvidenceBucket}
	err = retryUnavailable(ctx, func(ctx context.Context) error {
		return setupStep("objectstore/buckets", objectstore.EnsureSetupBuckets(ctx, c.ObjectStore.Endpoint, c.ObjectStore.Region, ca, admin, ids.InstallationID, buckets, policies, out))
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, "object store configured")
	return nil
}

// waitSchema polls with one runtime credential until the database serves
// this binary's schema. Deployments run it as an init container.
func waitSchema(ctx context.Context, path, credentialPath, caPath string, out io.Writer) error {
	raw, err := readSetupFile(path, contracts.OwnerDeploymentMaxBytes)
	if err != nil {
		return setupStep("configuration", err)
	}
	var config struct {
		Postgres struct {
			contracts.SetupPostgres
			Roots [][]byte `json:"roots"`
		} `json:"postgres"`
	}
	if json.Unmarshal(raw, &config) != nil {
		return setupStep("configuration", cfg.ErrInvalid)
	}
	var roots *x509.CertPool
	if caPath != "" {
		ca, err := readSetupFile(caPath, 64<<10)
		if err != nil {
			return setupStep("postgres/ca", err)
		}
		if roots, err = setupRoots(ca); err != nil {
			return setupStep("postgres/ca", err)
		}
	} else {
		roots = x509.NewCertPool()
		for _, der := range config.Postgres.Roots {
			certificate, err := x509.ParseCertificate(der)
			if err != nil {
				return setupStep("postgres/ca", cfg.ErrInvalid)
			}
			roots.AddCert(certificate)
		}
		if len(config.Postgres.Roots) == 0 {
			return setupStep("postgres/ca", cfg.ErrInvalid)
		}
	}
	credential, err := readSetupCredential(credentialPath)
	if err != nil {
		return setupStep("credential", err)
	}
	pg, err := setupPGConfig(config.Postgres.SetupPostgres, roots, credential)
	if err != nil {
		return setupStep("configuration", err)
	}
	pg.RuntimeParams = map[string]string{"application_name": "asservat-wait-schema", "statement_timeout": "5000ms"}
	for {
		state, err := currentSchema(ctx, pg)
		if err == nil && state.Compatible(postgres.CompiledSchemaVersion) {
			_, _ = fmt.Fprintf(out, "schema %d is current\n", state.Head)
			return nil
		}
		if errors.Is(err, cfg.ErrChanged) || err == nil && state.Floor > postgres.CompiledSchemaVersion {
			// A newer database that no longer serves this binary.
			return setupStep("schema", cfg.ErrChanged)
		}
		select {
		case <-ctx.Done():
			return setupStep("schema", cfg.ErrUnavailable)
		case <-time.After(2 * time.Second):
		}
	}
}

func currentSchema(ctx context.Context, c *pgx.ConnConfig) (postgres.SchemaState, error) {
	conn, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		return postgres.SchemaState{}, cfg.ErrUnavailable
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	state, err := postgres.ReadSchemaState(ctx, conn)
	if errors.Is(err, cfg.ErrChanged) {
		return state, err
	}
	if err != nil {
		return state, cfg.ErrUnavailable
	}
	return state, nil
}
