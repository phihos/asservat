package integration

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Explicit synthetic protected seed only. SQL role creation, original SCRAM,
// migrations, purpose roles, encrypted audit, activation, history ACL transfer
// and session termination below are actual service operations. Native bootstrap
// guard/UID provenance and original-Pod handover require their separate fixture.
type syntheticManagerRoot struct {
	mu                  sync.Mutex
	state               contracts.InitialBootstrapState
	claims, completions int
	loseCompletion      bool
}

func (r *syntheticManagerRoot) snapshot() contracts.InitialBootstrapState {
	b, _ := json.Marshal(r.state)
	defer clear(b)
	var s contracts.InitialBootstrapState
	_ = json.Unmarshal(b, &s)
	return s
}
func (r *syntheticManagerRoot) ClaimBootstrapSQLManager(ctx context.Context, oid uint32, start time.Time) (contracts.InitialBootstrapState, bool, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.InitialBootstrapState{}, false, time.Time{}, cfg.ErrUnavailable
	}
	fresh := r.state.Manager == nil
	if fresh {
		n := time.Now().UTC().Truncate(time.Microsecond)
		r.state.Manager = &contracts.InitialBootstrapManager{OperationID: custodyID(), StartedAt: n, Until: n.Add(30 * time.Minute), DatabaseOID: oid, PostmasterAt: start}
		r.claims++
	}
	return r.snapshot(), fresh, time.Now().Add(5 * time.Second), nil
}
func (r *syntheticManagerRoot) ReadBootstrapSQLManager(ctx context.Context) (contracts.InitialBootstrapState, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.InitialBootstrapState{}, time.Time{}, cfg.ErrUnavailable
	}
	return r.snapshot(), time.Now().Add(5 * time.Second), nil
}
func (r *syntheticManagerRoot) CompleteBootstrapSQLManager(ctx context.Context, s contracts.InitialBootstrapState, until time.Time, pin contracts.InitialSQLHistoryManager) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil || !time.Now().Before(until) || r.state.Manager.OperationID != s.Manager.OperationID {
		return cfg.ErrUnavailable
	}
	r.state.Manager.Receipt = &pin
	r.completions++
	if r.loseCompletion {
		r.loseCompletion = false
		return cfg.ErrUnavailable
	}
	return nil
}

func TestInitialBootstrapManagerWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run selected owned PostgreSQL/S3/OpenBao fixture")
	}
	var f fixture
	raw, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(raw, &f) != nil || f.Postgres == "" || f.KMS == "" || f.S3 == "" {
		t.Fatal("fixture unavailable")
	}
	clear(raw)
	ctx, end := context.WithTimeout(context.Background(), 120*time.Second)
	defer end()
	admin, e := pgxpool.New(ctx, f.Postgres)
	if e != nil {
		t.Fatal("fixture administration unavailable")
	}
	t.Cleanup(admin.Close)
	database := "bootstrap_" + strings.ReplaceAll(custodyID(), "-", "")
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); e != nil {
		t.Fatal("owned database unavailable")
	}
	installation := custodyID()
	managerName := "asservat_init_" + strings.ReplaceAll(installation, "-", "") + "_manager"
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, e := admin.Exec(bounded, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()); e != nil {
			t.Error("owned database cleanup failed")
		}
		for _, facet := range []string{"prepare", "audit", "activate", "history", "manager"} {
			name := "asservat_init_" + strings.ReplaceAll(installation, "-", "") + "_" + facet
			if _, e := admin.Exec(bounded, "DROP ROLE IF EXISTS "+pgx.Identifier{name}.Sanitize()); e != nil {
				t.Error("owned role cleanup failed")
			}
		}
	})
	endpoint, e := url.Parse(f.Postgres)
	if e != nil {
		t.Fatal("fixture endpoint unavailable")
	}
	address, roots := pgTLSBridge(t, endpoint.Host)
	host, portText, e := net.SplitHostPort(address)
	if e != nil {
		t.Fatal("TLS fixture unavailable")
	}
	port, _ := strconv.Atoi(portText)
	sqlConfig := admin.Config().ConnConfig.Copy()
	sqlConfig.Host, sqlConfig.Port, sqlConfig.Database = host, uint16(port), database
	sqlConfig.TLSConfig = roots.Clone()
	sqlConfig.TLSConfig.MinVersion = tls.VersionTLS13
	sqlConfig.Fallbacks = nil
	databaseAdmin, e := pgx.ConnectConfig(ctx, sqlConfig)
	if e != nil {
		t.Fatal("owned database connection unavailable")
	}
	defer databaseAdmin.Close(context.Background())
	root := &syntheticManagerRoot{state: contracts.InitialBootstrapState{Format: contracts.InitialBootstrapStateFormat, InstallationID: installation, RequestID: custodyID(), ClusterID: custodyID(), IssuerEpoch: custodyID(), SeedUID: custodyID()}, loseCompletion: true}
	for i, p := range []*string{&root.state.Passwords.Manager, &root.state.Passwords.Preparation, &root.state.Passwords.Audit, &root.state.Passwords.Activation, &root.state.Passwords.History} {
		*p = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(rune('a'+i)), 32)))
	}
	manager, e := postgres.NewInitialSQLManager(ctx, sqlConfig, root)
	if e != nil {
		t.Fatal("trusted manager constructor", e)
	}
	defer manager.Close()
	t.Run("unknown-completion-preserves-original-role", func(t *testing.T) {
		if _, e = manager.Provision(ctx); e == nil || root.state.Manager.Receipt == nil {
			t.Fatal("lost completion did not retain original SQL role")
		}
		pin := *root.state.Manager.Receipt
		until := root.state.Manager.Until
		again, e := manager.Provision(ctx)
		if e != nil || again != pin || root.claims != 1 || !root.state.Manager.Until.Equal(until) {
			t.Fatal("exact lookup renewed/replaced manager", e)
		}
		var correct bool
		if e = databaseAdmin.QueryRow(ctx, "SELECT rolcanlogin AND rolcreaterole AND NOT rolsuper AND rolvaliduntil=$2 FROM pg_roles WHERE oid=$1", pin.OID, until).Scan(&correct); e != nil || !correct {
			t.Fatal("original finite manager unavailable")
		}
	})
	pin := *root.state.Manager.Receipt
	schemaRoot := &syntheticSchemaRoot{}
	schema, e := postgres.NewInitialSchema(sqlConfig, schemaRoot, pin)
	if e != nil {
		t.Fatal("schema constructor", e)
	}
	defer schema.Close()
	if e = schema.Run(ctx); e != nil {
		t.Fatal("actual pristine schema", e)
	}
	if _, e = manager.Provision(ctx); e != nil {
		t.Fatal("manager exact grant-union replay", e)
	}
	managerConfig := sqlConfig.Copy()
	managerConfig.User, managerConfig.Password, managerConfig.RequireAuth = pin.Name, root.state.Passwords.Manager, "scram-sha-256"
	pc, e := pgxpool.ParseConfig("")
	if e != nil {
		t.Fatal(e)
	}
	pc.ConnConfig = managerConfig
	pc.MaxConns = 2
	pc.MinConns = 0
	preparationPool, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		t.Fatal(e)
	}
	defer preparationPool.Close()
	roles, e := postgres.NewInitialSQLRoles(ctx, preparationPool, installation)
	if e != nil {
		t.Fatal(e)
	}
	credentialsPlan, e := postgres.NewInitialSQLCredentials(installation, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	credentialsPlan.Preparation.Password = root.state.Passwords.Preparation
	credentialsPlan.Audit.Password = root.state.Passwords.Audit
	credentialsPlan.Activation.Password = root.state.Passwords.Activation
	if e = roles.Provision(ctx, credentialsPlan); e != nil {
		t.Fatal("purpose roles", e)
	}
	historyName, e := postgres.InitialSQLHistoryRoleName(installation)
	if e != nil {
		t.Fatal(e)
	}
	historyLogin := postgres.InitialSQLLogin{Username: historyName, Password: root.state.Passwords.History}
	if e = roles.ProvisionHistory(ctx, credentialsPlan, historyLogin, pin); e != nil {
		t.Fatal("history role", e)
	}
	if _, _, e = postgres.VerifyInitialSchemaCompletion(ctx, managerConfig, schemaRoot); e != nil {
		t.Fatal("original completed schema rejected legitimate creator memberships", e)
	}
	scope := value.InstallationWitnessScope{InstallationID: installation, IssuerEpoch: root.state.IssuerEpoch, ClusterID: root.state.ClusterID, Namespace: "control", NamespaceUID: custodyID(), Name: "witness", UID: custodyID(), WriterAccount: "installer", WriterAccountUID: custodyID()}
	plan := artifact.Digest{2}
	witness := &initialWitnessFixture{scope: scope}
	authority := &initialAdminFixture{a: value.Administration{InstallationID: installation, IssuerEpoch: scope.IssuerEpoch, Issuer: "https://id.example.test", Revision: identity.Revision{UID: "initial-fleet", Generation: 1, Digest: artifact.Digest{1}}, Clients: []string{"console"}, Groups: []string{"operators"}, DeliveryProfiles: []string{"ops"}, MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16}}
	poolForLogin := func(login postgres.InitialSQLLogin) *pgxpool.Pool {
		c := pc.Copy()
		c.ConnConfig = sqlConfig.Copy()
		c.ConnConfig.User, c.ConnConfig.Password, c.ConnConfig.RequireAuth = login.Username, login.Password, "scram-sha-256"
		p, e := pgxpool.NewWithConfig(ctx, c)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(p.Close)
		return p
	}
	prepPool, ackPool, actPool := poolForLogin(credentialsPlan.Preparation), poolForLogin(credentialsPlan.Audit), poolForLogin(credentialsPlan.Activation)
	defer prepPool.Close()
	defer ackPool.Close()
	defer actPool.Close()
	prep, e := postgres.NewInitialInstallations(ctx, prepPool, scope, plan)
	if e != nil {
		t.Fatal(e)
	}
	ack, e := postgres.NewInitialInstallations(ctx, ackPool, scope, plan)
	if e != nil {
		t.Fatal(e)
	}
	activation, e := postgres.NewInitialInstallations(ctx, actPool, scope, plan)
	if e != nil {
		t.Fatal(e)
	}
	objects := initialBootstrapAuditObjects(t, ctx, f)
	installer := app.InitialInstaller{Witness: witness, Consume: witness, Administration: authority, Preparation: prep, Objects: objects, Acknowledgements: ack, Activation: activation, Now: time.Now}
	if _, e = installer.Activate(ctx); e != nil {
		t.Fatal("real audited SQL activation", e)
	}
	historyPool := poolForLogin(historyLogin)
	defer historyPool.Close()
	readAuthority := &initialHistoryAuthorityFixture{}
	readAuthority.reset(5*time.Second, false, 0)
	history, e := postgres.NewInitialInstallationReader(ctx, historyPool, scope, plan, readAuthority)
	if e != nil {
		t.Fatal(e)
	}
	old, e := pgx.ConnectConfig(ctx, managerConfig)
	if e != nil {
		t.Fatal("original manager session unavailable")
	}
	defer old.Close(context.Background())
	t.Run("flags-alone-do-not-close-existing-session", func(t *testing.T) {
		if _, e = databaseAdmin.Exec(ctx, "ALTER ROLE "+pgx.Identifier{managerName}.Sanitize()+" NOLOGIN NOCREATEROLE"); e != nil {
			t.Fatal(e)
		}
		var n int
		if e = old.QueryRow(ctx, "SELECT count(*) FROM fleet_initial_activation").Scan(&n); e != nil || n != 1 {
			t.Fatal("test did not demonstrate existing-session authority")
		}
		if _, e = databaseAdmin.Exec(ctx, "ALTER ROLE "+pgx.Identifier{managerName}.Sanitize()+" LOGIN CREATEROLE"); e != nil {
			t.Fatal("fault reset", e)
		}
	})
	t.Run("restrict-revoke-needs-exact-history-transfer", func(t *testing.T) {
		_, e = databaseAdmin.Exec(ctx, "REVOKE SELECT ON fleet_initial_activation FROM "+pgx.Identifier{managerName}.Sanitize()+" RESTRICT")
		var pg *pgconn.PgError
		if !errors.As(e, &pg) || pg.Code != "2BP01" {
			t.Fatal("history grant dependency was not retained", e)
		}
	})
	// Positive three-facet retirement and joined preparation pool precede trusted
	// manager closure. The retained old connection deliberately models a stray
	// already-authenticated connection, which the manager must terminate.
	if e = roles.Retire(ctx, credentialsPlan); e != nil {
		t.Fatal("purpose credential retirement", e)
	}
	preparationPool.Close()
	prepPool.Close()
	ackPool.Close()
	actPool.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	root.state.Manager.Closing = &contracts.InitialBootstrapClose{OperationID: custodyID(), StartedAt: now, Until: now.Add(30 * time.Second)}
	readAuthority.reset(5*time.Second, false, 0)
	completed, e := manager.Retire(ctx, history)
	if e != nil || completed.IsZero() {
		t.Fatal("qualified manager retirement", e)
	}
	if _, e = old.Exec(ctx, "SELECT count(*) FROM fleet_initial_activation"); e == nil {
		t.Fatal("old manager connection kept effects after retirement")
	}
	if e = postgres.CheckInitialSQLHistoryRole(ctx, historyPool, installation, pin); e != nil {
		t.Fatal("exact passive history rights changed", e)
	}
	readAuthority.reset(5*time.Second, false, 0)
	observation, e := history.ObserveInitialInstallation(ctx)
	if e != nil || observation.Disposition != app.InitialInstallationActivated {
		t.Fatal("passive history unavailable after grant transfer", e)
	}
	if later, e := pgx.ConnectConfig(ctx, managerConfig); e == nil {
		later.Close(ctx)
		t.Fatal("retired original password authenticated")
	}
	readAuthority.reset(5*time.Second, false, 0)
	replayed, e := manager.Retire(ctx, history)
	if e != nil || !replayed.Equal(completed) {
		t.Fatal("exact retired SQL marker lookup failed", e)
	}
	if _, e = manager.Provision(ctx); e == nil {
		t.Fatal("retired manager reopened")
	}
	t.Log("actual generated finite manager, original schema, child/history roles, encrypted activation, measured history grant transfer and old-session termination; Kubernetes seed/witness/read authority synthetic")
}

func initialBootstrapAuditObjects(t *testing.T, ctx context.Context, f fixture) *objectstore.InitialInstallationObjects {
	t.Helper()
	name := "bootstrap-" + strings.ReplaceAll(custodyID(), "-", "")
	request(t, f.KMS, "synthetic-root", "sys/mounts/"+name, map[string]any{"type": "transit"}, 204)
	request(t, f.KMS, "synthetic-root", name+"/keys/audit", map[string]any{"type": "aes256-gcm96"}, 200)
	tokens := map[string]string{}
	for _, op := range []string{"encrypt", "decrypt"} {
		policy := name + "-" + op
		request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+policy, map[string]any{"policy": `path "` + name + `/` + op + `/audit" { capabilities=["update"] }`}, 204)
		tokens[op] = request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{policy}, "no_default_policy": true, "ttl": "15m"}, 200)["auth"].(map[string]any)["client_token"].(string)
	}
	key := tlsBridge(t, f.KMS)
	seal, e := kms.NewSealer(key.URL, tokens["encrypt"], name, "audit", key.Client())
	if e != nil {
		t.Fatal(e)
	}
	open, e := kms.NewOpener(key.URL, tokens["decrypt"], name, "audit", key.Client())
	if e != nil {
		t.Fatal(e)
	}
	bridge := tlsBridge(t, f.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(bridge.URL), UsePathStyle: true, Credentials: creds, HTTPClient: bridge.Client()})
	if _, e = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &name}); e != nil {
		t.Fatal(e)
	}
	store, e := objectstore.New(bridge.URL, "us-east-1", name, creds, bridge.Client())
	if e != nil {
		t.Fatal(e)
	}
	return &objectstore.InitialInstallationObjects{Store: store, Seal: seal, Open: open}
}
