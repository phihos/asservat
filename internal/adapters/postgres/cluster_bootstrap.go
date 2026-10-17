package postgres

import (
	"context"
	"crypto/sha256"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ClusterBootstraps is the federation's generation-1 path (ADR-193). It calls
// only the three migration-00064 functions; no lineage is written directly.
type ClusterBootstraps struct {
	ledger       *Ledger
	installation string
}

func NewClusterBootstraps(ctx context.Context, pool *pgxpool.Pool, installation string) (*ClusterBootstraps, error) {
	if !authorization.UUID(installation) {
		return nil, fleet.ErrClusterCredentialDenied
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &ClusterBootstraps{ledger: l, installation: installation}, nil
}

// Reserve binds the claimed bootstrap, the generation-1 key and the staged
// source, and returns the minted lineage; the same call again returns it.
func (s *ClusterBootstraps) Reserve(ctx context.Context, bootstrap, root string, key []byte, source fleet.ClusterBootstrapSource, policy fleet.ClusterCredentialPolicy) (string, error) {
	if s == nil || ctx == nil || !authorization.UUID(bootstrap) || !authorization.UUID(root) || len(key) != 32 || !source.Valid() || !policy.Valid() {
		return "", fleet.ErrClusterCredentialDenied
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var lineage string
	err := s.ledger.pool.QueryRow(call, `SELECT public.reserve_cluster_bootstrap($1,$2,$3,$4,$5,$6,$7,$8,$9)::text`, s.installation, bootstrap, root, key, source.UID, source.Generation,
		source.ProtectionDigest[:], int64(policy.Validity/time.Second), int64(policy.Rotation/time.Second)).Scan(&lineage)
	if err != nil || !authorization.UUID(lineage) {
		return "", fleet.ErrClusterCredentialDenied
	}
	return lineage, nil
}

// Acknowledge records the verified generation-1 audit receipt once.
func (s *ClusterBootstraps) Acknowledge(ctx context.Context, record audit.ClusterBootstrap, receipt audit.Receipt) error {
	if s == nil || ctx == nil || record.InstallationID != s.installation || !receipt.ValidClusterBootstrap(record) {
		return fleet.ErrClusterCredentialDenied
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	if _, err := s.ledger.pool.Exec(call, `SELECT public.acknowledge_cluster_bootstrap($1,$2,$3,$4,$5,$6,$7)`, s.installation, record.BootstrapID, receipt.Key, receipt.Version, receipt.ETag, receipt.Bytes, receipt.SHA256[:]); err != nil {
		return fleet.ErrClusterCredentialDenied
	}
	return nil
}

// Activate writes generation 1 atomically, or returns the original result on
// a replay. A fenced lineage is ErrClusterCredentialFenced; a replay after
// use commits the fork fence before reporting it.
func (s *ClusterBootstraps) Activate(ctx context.Context, bootstrap string, secretDigest artifact.Digest, key []byte) (fleet.ClusterBootstrapResult, error) {
	var out fleet.ClusterBootstrapResult
	if s == nil || ctx == nil || !authorization.UUID(bootstrap) || secretDigest == (artifact.Digest{}) || len(key) != 32 {
		return out, fleet.ErrClusterCredentialDenied
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var lineage string
	var fenced *string
	err := s.ledger.pool.QueryRow(call, `SELECT lineage::text, generation, issued_at, valid_until, replay, fenced FROM public.activate_cluster_bootstrap($1,$2,$3,$4)`, s.installation, bootstrap, secretDigest[:], key).
		Scan(&lineage, &out.Generation, &out.IssuedAt, &out.ValidUntil, &out.Replay, &fenced)
	if err != nil {
		return fleet.ClusterBootstrapResult{}, fleet.ErrClusterCredentialDenied
	}
	if fenced != nil {
		return fleet.ClusterBootstrapResult{}, fleet.ErrClusterCredentialFenced
	}
	out.LineageID = lineage
	out.KeyDigest = artifact.Digest(clusterBootstrapSPKIDigest(key))
	if !out.Valid() {
		return fleet.ClusterBootstrapResult{}, fleet.ErrClusterCredentialDenied
	}
	return out, nil
}

// clusterBootstrapSPKIDigest is the SHA-256 of the Ed25519 SubjectPublicKeyInfo,
// the digest the enrollment claim records.
func clusterBootstrapSPKIDigest(key []byte) [32]byte {
	return sha256.Sum256(append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}, key...))
}
