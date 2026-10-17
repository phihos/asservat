package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Separate synthetic fixture read authority. Neither this SQL role nor the
// upstream decrypt token is mounted into the generated worker. It never calls
// observation/acknowledgement methods and has no grants on acceptance fields.
type providerWorkerWitness struct {
	pool   *pgxpool.Pool
	reader *postgres.OwnerConfigurations
	store  *objectstore.Store
	opener *kms.Opener
	input  contracts.HubWorkerDeployment
}

func newProviderWorkerWitness(t *testing.T, ctx context.Context, config *pgx.ConnConfig, input contracts.HubWorkerDeployment, providers *initialRuntimeNativeProviders) *providerWorkerWitness {
	t.Helper()
	admin, err := pgx.ConnectConfig(ctx, config.Copy())
	if err != nil {
		t.Fatal("fixture witness administrator", err)
	}
	defer admin.Close(ctx)
	name := "fixture_worker_witness_" + strings.ReplaceAll(custodyID(), "-", "")
	role := pgx.Identifier{name}.Sanitize()
	password := "synthetic-worker-witness-" + custodyID()
	if _, err = admin.Exec(ctx, "CREATE ROLE "+role+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 1 PASSWORD '"+password+"'"); err != nil {
		t.Fatal(err)
	}
	// Column UPDATE is PostgreSQL's required row-lock privilege. Source generation,
	// observation deadlines, audit JSON, recovery and activation have no grants.
	statements := []string{
		"GRANT USAGE ON SCHEMA public TO " + role,
		"GRANT SELECT ON goose_db_version,fleet_current_trust,hub_owner_configuration,hub_owner_configuration_revision TO " + role,
		"GRANT UPDATE(installation_id) ON fleet_current_trust TO " + role,
		"GRANT UPDATE(source_uid) ON hub_owner_configuration TO " + role,
	}
	for _, statement := range statements {
		if _, err = admin.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	pc, err := pgxpool.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig = config.Copy()
	pc.ConnConfig.User = name
	pc.ConnConfig.Password = password
	pc.MaxConns = 1
	pc.MinConns = 0
	pc.ConnConfig.RuntimeParams = map[string]string{"application_name": "asservat-native-worker-witness", "statement_timeout": "5000ms", "lock_timeout": "1000ms", "idle_in_transaction_session_timeout": "5000ms"}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	w := &providerWorkerWitness{pool: pool, input: input}
	t.Cleanup(w.close)
	var denied bool
	err = pool.QueryRow(ctx, `SELECT NOT has_column_privilege(current_user,'hub_owner_configuration','observed_at','UPDATE') AND NOT has_column_privilege(current_user,'hub_owner_configuration','fresh_until','UPDATE') AND NOT has_column_privilege(current_user,'hub_owner_configuration_revision','audit_receipt_json','UPDATE') AND NOT has_table_privilege(current_user,'hub_owner_configuration_revision','INSERT') AND NOT has_table_privilege(current_user,'fleet_trust','UPDATE')`).Scan(&denied)
	if err != nil || !denied {
		t.Fatal("fixture observer acquired acceptance writes", err)
	}
	w.reader, err = postgres.NewOwnerConfigurations(ctx, pool, input.InstallationID, input.ClusterID, input.Namespace.UID, input.OwnerSource.UID)
	if err != nil {
		t.Fatal("concrete read-only accepted configuration observer", err)
	}
	acl, _ := json.Marshal(map[string]any{"path": map[string]any{input.KeyService.AuditMount + "/decrypt/" + input.KeyService.AuditKey: map[string]any{"capabilities": []string{"update"}}}})
	policy := "fixture-worker-audit-read"
	providers.admin(t, ctx, http.MethodPost, "sys/policies/acl/"+policy, map[string]string{"policy": string(acl)}, 204)
	raw := providers.admin(t, ctx, http.MethodPost, "auth/token/create", map[string]any{"policies": []string{policy}, "no_default_policy": true, "renewable": false, "ttl": "5m", "explicit_max_ttl": "5m"}, 200)
	var response struct {
		Auth struct {
			Token string `json:"client_token"`
		} `json:"auth"`
	}
	if json.Unmarshal(raw, &response) != nil || response.Auth.Token == "" {
		clear(raw)
		t.Fatal("independent fixture audit decrypt credential unavailable")
	}
	clear(raw)
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		providers.admin(t, c, http.MethodPost, "auth/token/revoke", map[string]string{"token": response.Auth.Token}, 204)
	})
	w.opener, err = kms.NewOpener(input.KeyService.Endpoint, response.Auth.Token, input.KeyService.AuditMount, input.KeyService.AuditKey, providers.client)
	if err != nil {
		t.Fatal(err)
	}
	w.store, err = objectstore.NewVersionedAudit(input.AuditStore.Endpoint, input.AuditStore.Region, input.AuditStore.Bucket, credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), providers.client)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *providerWorkerWitness) close() {
	if w == nil {
		return
	}
	if w.opener != nil {
		w.opener.Close()
	}
	if w.store != nil {
		w.store.Close()
	}
	if w.pool != nil {
		w.pool.Close()
	}
}

func (w *providerWorkerWitness) verifyAudit(ctx context.Context, c fleet.OwnerConfiguration) error {
	var encoded []byte
	err := w.pool.QueryRow(ctx, `SELECT audit_receipt_json FROM hub_owner_configuration_revision WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 AND generation=$4`, w.input.InstallationID, w.input.ClusterID, w.input.OwnerSource.UID, c.Revision.Generation).Scan(&encoded)
	if err != nil {
		return err
	}
	var r audit.Receipt
	if json.Unmarshal(encoded, &r) != nil || !r.ValidOwnerConfiguration(c) {
		return errors.New("actual acknowledged receipt unavailable")
	}
	pinned, err := w.store.Pin(objectstore.Object{Key: r.Key, VersionID: r.Version, ETag: r.ETag, Bytes: r.Bytes, SHA256: r.SHA256})
	if err != nil {
		return err
	}
	raw, err := pinned.ReadRange(ctx, 0, r.Bytes)
	if err != nil {
		return err
	}
	defer clear(raw)
	if sha256.Sum256(raw) != r.SHA256 {
		return errors.New("actual acknowledged audit digest changed")
	}
	return framed.VerifyOwnerConfiguration(ctx, w.opener, c, raw)
}

// Include every immutable original revision and audit byte, while excluding
// head freshness/negative watermarks that the independent observer must fence.
func (w *providerWorkerWitness) history(ctx context.Context) ([]byte, error) {
	var raw []byte
	err := w.pool.QueryRow(ctx, `SELECT coalesce(jsonb_agg(jsonb_build_array(generation,encode(snapshot_json,'hex'),encode(audit_receipt_json,'hex')) ORDER BY generation),'[]'::jsonb)::text FROM hub_owner_configuration_revision WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3`, w.input.InstallationID, w.input.ClusterID, w.input.OwnerSource.UID).Scan(&raw)
	return raw, err
}
