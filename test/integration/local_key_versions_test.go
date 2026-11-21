package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	corev1 "k8s.io/api/core/v1"
)

func qualifyRetainedLocalKeyVersions(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool) {
	t.Helper()
	trust := newRecoveryEffectFixtures(t, ctx, admin)(t, custodyID())
	scope := authorization.KeyScope{InstallationID: trust.installation, Purpose: "artifact", KeyID: "synthetic"}
	role, _ := postgres.PublicRuntimeRoleName(trust.installation, "key-configuration")
	if _, err := admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN PASSWORD 'fixture-only'"); err != nil {
		t.Fatal(err)
	}
	grants, ok := postgres.PublicRuntimeRoleGrantSQL("key-configuration", role)
	if !ok {
		t.Fatal("missing key-configuration grants")
	}
	for _, grant := range grants {
		if _, err := admin.Exec(ctx, grant); err != nil {
			t.Fatal(err)
		}
	}
	c := authorization.LocalKeyConfiguration{Scope: scope, ClusterID: custodyID(), NamespaceUID: "synthetic", RecoveryEpoch: fixtureIssuerEpoch(t, ctx, admin, scope.InstallationID), Revision: identity.Revision{UID: "mount", Generation: 1, Digest: artifact.Digest{1}}, SecretUID: "key", SecretDigest: artifact.Digest{1}, ActiveVersion: 1}
	pool := poolFor(role, "fixture-only")
	defer pool.Close()
	ledger, err := postgres.NewLocalKeyConfigurations(ctx, pool, scope, c.ClusterID, c.NamespaceUID, c.Revision.UID)
	if err != nil {
		t.Fatal(err)
	}
	observe := func() error {
		c.ObservedAt = time.Now().UTC()
		c.FreshUntil = c.ObservedAt.Add(5 * time.Second)
		_, err := ledger.ObserveLocalKeys(ctx, c)
		return err
	}
	c.Versions = []authorization.LocalKeyVersion{{Version: 1, Fingerprint: artifact.Digest{1}}}
	if err := observe(); err != nil {
		t.Fatal("original version", err)
	}
	// 8,192 key entries fit inside the mounted Secret. The corresponding
	// public fingerprint JSON exceeds 1 MiB and must survive a second read.
	for i := 2; i <= 8192; i++ {
		c.Versions = append(c.Versions, authorization.LocalKeyVersion{Version: i, Fingerprint: sha256.Sum256([]byte(strconv.Itoa(i)))})
	}
	c.ActiveVersion = len(c.Versions)
	c.Revision.Generation = int64(c.ActiveVersion)
	c.Revision.Digest, c.SecretDigest = artifact.Digest{2}, artifact.Digest{2}
	snapshot, err := json.Marshal(c)
	if err != nil || len(snapshot) <= corev1.MaxSecretSize {
		t.Fatal("fixture needs expanded SQL fingerprint representation", len(snapshot), err)
	}
	for range 2 {
		if err := observe(); err != nil {
			t.Fatal("expanded key snapshot", err)
		}
	}
	var count int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM local_key_version WHERE installation_id=$1 AND purpose=$2 AND key_id=$3", scope.InstallationID, scope.Purpose, scope.KeyID).Scan(&count); err != nil || count != len(c.Versions) {
		t.Fatal("retained fingerprint rows", count, err)
	}
	c.Revision.Generation++
	c.Versions[128].Fingerprint = artifact.Digest{42}
	if err := observe(); err == nil {
		t.Fatal("changed material for a retained version was accepted")
	}
}
