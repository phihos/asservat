package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ADR-168 against real PostgreSQL, using the connector-identity fixture's
// accepted profile. Synthetic keys and exporter values; no TLS, no audit.
func qualifyClusterEnrollmentCredential(t *testing.T, ctx context.Context, poolFor func(string, string) *pgxpool.Pool, f *connectorSQLFixture) {
	t.Helper()
	pool := poolFor("cluster_credential_runtime", "synthetic-cluster-credential")
	store, err := postgres.NewClusterCredentials(ctx, pool, f.scenario.a.RootID)
	if err != nil {
		t.Fatal("cluster credential store", err)
	}
	verifier := fleetapp.ClusterCredentialVerifier{Store: store}
	b := f.process.Binding
	profile := value.ClusterCredentialProfile{RootID: f.scenario.a.RootID, PeerID: b.PeerID, InstallationID: b.InstallationID, ClusterID: b.ClusterID}
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		public, private, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return public, private
	}
	exporter := make([]byte, 32)
	_, _ = rand.Read(exporter)
	present := func(r value.ClusterCredentialRequest, private ed25519.PrivateKey) (value.ClusterCredentialPresentation, error) {
		r.RequestedAt = time.Now().UTC().Truncate(time.Microsecond)
		sig, e := fleetapp.SignClusterCredentialRequest(private, r, exporter)
		if e != nil {
			t.Fatal(e)
		}
		return verifier.Present(ctx, r, sig, exporter)
	}
	public1, private1 := key()
	// ADR-193: no login inserts a lineage directly; generation 1 comes only
	// through the bootstrap functions.
	var pg *pgconn.PgError
	if _, denied := pool.Exec(ctx, `INSERT INTO cluster_enrollment_lineage(lineage_id,root_id,peer_id,installation_id,cluster_id,validity_seconds,rotation_seconds,current_generation,created_at) VALUES($1,$2,$3,$4,$5,604800,86400,1,clock_timestamp())`,
		custodyID(), profile.RootID, profile.PeerID, profile.InstallationID, profile.ClusterID); !errors.As(denied, &pg) || (pg.Code != "42501" && pg.Code != "23514") {
		t.Fatal("direct lineage insert", denied)
	}
	bootstraps, bootstrap, secret, lineage := clusterBootstrapGenerationOne(t, ctx, f.admin, pool, profile, public1)
	if again, e := bootstraps.Activate(ctx, bootstrap, secret, public1); e != nil || !again.Replay || again.LineageID != lineage {
		t.Fatal("bootstrap replay", again, e)
	}
	admission := value.ClusterCredentialRequest{Operation: value.ClusterAdmission, Profile: profile, Generation: 1, PodUID: custodyID(), ProcessEpoch: custodyID(), ClientKey: [32]byte{1}, ServerKey: [32]byte{2}}
	got, err := present(admission, private1)
	if err != nil || !got.Valid(time.Now()) || got.Generation != 1 || got.Profile != profile {
		t.Fatal("current admission", got, err)
	}
	_, impostor := key()
	if _, err = present(admission, impostor); !errors.Is(err, value.ErrClusterCredentialDenied) {
		t.Fatal("foreign key admitted", err)
	}
	public2, private2 := key()
	rotate := value.ClusterCredentialRequest{Operation: value.ClusterRotation, Profile: profile, Generation: 1, NextKey: public2}
	if got, err = present(rotate, private1); err != nil || got.Generation != 2 {
		t.Fatal("rotation", got, err)
	}
	// The uncertain reply's exact retry is idempotent within the overlap.
	if got, err = present(rotate, private1); err != nil || got.Generation != 2 {
		t.Fatal("exact rotation replay", got, err)
	}
	admission.Generation = 2
	if _, err = present(admission, private2); err != nil {
		t.Fatal("successor admission", err)
	}
	// After the successor's first use the old key can only be a copy: fence.
	if _, err = present(rotate, private1); !errors.Is(err, value.ErrClusterCredentialFenced) {
		t.Fatal("old key after successor use not fenced", err)
	}
	if _, err = present(admission, private2); !errors.Is(err, value.ErrClusterCredentialFenced) {
		t.Fatal("fenced lineage still admits", err)
	}
	var fenced string
	if err = f.admin.QueryRow(ctx, "SELECT fenced FROM cluster_enrollment_lineage WHERE root_id=$1 AND peer_id=$2 AND retired_at IS NULL", profile.RootID, profile.PeerID).Scan(&fenced); err != nil || fenced != "fork" {
		t.Fatal("fork fence not committed", fenced, err)
	}
	// The SQL guard keeps history append-only, even for a privileged writer.
	for _, statement := range []string{
		"UPDATE cluster_enrollment_lineage SET fenced=NULL,fenced_at=NULL WHERE root_id=$1",
		"DELETE FROM cluster_enrollment_credential WHERE lineage_id IN (SELECT lineage_id FROM cluster_enrollment_lineage WHERE root_id=$1)",
	} {
		_, denied := pool.Exec(ctx, statement, profile.RootID)
		var pg *pgconn.PgError
		if !errors.As(denied, &pg) || (pg.Code != "23514" && pg.Code != "42501") {
			t.Fatal("cluster enrollment history mutated", statement, denied)
		}
	}
	// A bootstrap replay on the fenced lineage reports the fence.
	if _, err = bootstraps.Activate(ctx, bootstrap, secret, public1); !errors.Is(err, value.ErrClusterCredentialFenced) {
		t.Fatal("bootstrap replay on a fenced lineage", err)
	}
	if err = store.Revoke(ctx, profile); err != nil {
		t.Fatal("revoke", err)
	}
	t.Log("ADR-168/193 cluster enrollment credential: bootstrap generation 1 and replay, admission, rotation, replay, fork fence, append-only guard and direct-insert refusal on real PostgreSQL")
}
