package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// clusterBootstrapGenerationOne enrolls generation 1 through the ADR-193
// bootstrap functions. The claimed, claim-audited fleet bootstrap row is
// synthetic setup authority written by the administrator; reservation,
// audit acknowledgement and activation run through store, the runtime login.
// The profile must already be staged. It returns the store, bootstrap ID,
// secret digest and lineage.
func clusterBootstrapGenerationOne(t *testing.T, ctx context.Context, admin, runtime *pgxpool.Pool, p value.ClusterCredentialProfile, public ed25519.PublicKey) (*postgres.ClusterBootstraps, string, artifact.Digest, string) {
	t.Helper()
	var epoch, sourceUID string
	var generation int64
	var protection []byte
	if err := admin.QueryRow(ctx, `SELECT issuer_epoch::text, source_uid::text, source_generation, protection_digest FROM connector_identity_profile WHERE root_id=$1 AND peer_id=$2`, p.RootID, p.PeerID).Scan(&epoch, &sourceUID, &generation, &protection); err != nil {
		t.Fatal("staged profile for bootstrap", err)
	}
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	secretDigest := sha256.Sum256(secret)
	bootstrap, issue := custodyID(), make([]byte, 32)
	issue[0] = 9
	if _, err := admin.Exec(ctx, `INSERT INTO fleet_bootstrap(installation_id,id,cluster_id,peer_id,issuer_epoch,secret_sha256,not_before,not_after,issue_authority_digest,issue_audit_id,issue_audit_key,issue_audit_version,issue_audit_sha256)
		VALUES($1,$2,$3,$4,$5,$6,date_trunc('milliseconds',clock_timestamp())-interval '1 second',date_trunc('milliseconds',clock_timestamp())+interval '4 minutes',$7,$8,'synthetic-issue-audit','1',$7)`,
		p.InstallationID, bootstrap, p.ClusterID, p.PeerID, epoch, secretDigest[:], issue, custodyID()); err != nil {
		t.Fatal("synthetic bootstrap", err)
	}
	spki := sha256.Sum256(append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}, public...))
	claim := sha256.Sum256(append([]byte("synthetic-claim-audit"), bootstrap...))
	if _, err := admin.Exec(ctx, `UPDATE fleet_bootstrap SET claimed_at=clock_timestamp(), public_key_sha256=$3 WHERE installation_id=$1 AND id=$2`, p.InstallationID, bootstrap, spki[:]); err != nil {
		t.Fatal("synthetic bootstrap claim", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE fleet_bootstrap SET claim_acknowledged_at=clock_timestamp(), claim_audit_digest=$3, claim_object_key='synthetic-claim', claim_object_version='1', claim_object_etag='synthetic', claim_object_bytes=1, claim_object_sha256=$3 WHERE installation_id=$1 AND id=$2`, p.InstallationID, bootstrap, claim[:]); err != nil {
		t.Fatal("synthetic claim audit", err)
	}
	store, err := postgres.NewClusterBootstraps(ctx, runtime, p.InstallationID)
	if err != nil {
		t.Fatal("bootstrap store", err)
	}
	var digest artifact.Digest
	copy(digest[:], protection)
	source := value.ClusterBootstrapSource{UID: sourceUID, Generation: generation, ProtectionDigest: digest}
	lineage, err := store.Reserve(ctx, bootstrap, p.RootID, public, source, value.DefaultClusterCredentialPolicy())
	if err != nil {
		t.Fatal("bootstrap reservation", err)
	}
	record := audit.ClusterBootstrap{InstallationID: p.InstallationID, BootstrapID: bootstrap, RootID: p.RootID, ClusterID: p.ClusterID, PeerID: p.PeerID, IssuerEpoch: epoch, LineageID: lineage,
		KeyDigest: spki, ClaimAuditDigest: claim, SourceUID: sourceUID, SourceGeneration: generation, ProtectionDigest: digest, ReservedAt: time.Now().UTC().Truncate(time.Microsecond)}
	receipt := audit.Receipt{Key: audit.ClusterBootstrapAuditKey(record), Version: "1", ETag: "synthetic", Bytes: 1, SHA256: artifact.Digest{7}}
	if err = store.Acknowledge(ctx, record, receipt); err != nil {
		t.Fatal("bootstrap audit acknowledgement", err)
	}
	result, err := store.Activate(ctx, bootstrap, secretDigest, public)
	if err != nil || result.LineageID != lineage || result.Generation != 1 || result.Replay {
		t.Fatal("bootstrap activation", result, err)
	}
	return store, bootstrap, secretDigest, lineage
}
