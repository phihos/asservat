package fleet

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"time"

	auditport "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
)

// ClusterBootstrapLedger is the migration-00064 path: reserve, acknowledge
// the generation-1 audit, then activate atomically.
type ClusterBootstrapLedger interface {
	Reserve(context.Context, string, string, []byte, value.ClusterBootstrapSource, value.ClusterCredentialPolicy) (string, error)
	Acknowledge(context.Context, audit.ClusterBootstrap, audit.Receipt) error
	Activate(context.Context, string, artifact.Digest, []byte) (value.ClusterBootstrapResult, error)
}

// ClusterBootstrapAuditWriter writes the encrypted generation-1 audit record.
type ClusterBootstrapAuditWriter interface {
	WriteClusterBootstrap(context.Context, audit.ClusterBootstrap) (audit.Receipt, error)
}

// ClusterBootstrapStage binds the conversation to the claimed slot and reads
// and stages the delegated source within one bounded observation; it returns
// the staged source fields.
type ClusterBootstrapStage func(context.Context, value.Enrollment) (value.ClusterBootstrapSource, error)

// ClusterBootstrapActivation enrolls generation 1 in one hub conversation
// (ADR-193): claim and its audit, staging, reservation, the generation-1
// audit, then the atomic activation. A replay returns the original result.
type ClusterBootstrapActivation struct {
	Claims       EnrollmentLedger
	ClaimAudits  auditport.EnrollmentClaimLedger
	ClaimObjects auditport.EnrollmentClaimWriter
	Bootstraps   ClusterBootstrapLedger
	Audit        ClusterBootstrapAuditWriter
	Policy       value.ClusterCredentialPolicy
	Now          func() time.Time
}

func (s ClusterBootstrapActivation) Activate(ctx context.Context, r value.ClusterBootstrapRequest, key ed25519.PublicKey, stage ClusterBootstrapStage) (value.ClusterBootstrapResult, error) {
	var zero value.ClusterBootstrapResult
	if s.Claims == nil || s.ClaimAudits == nil || s.ClaimObjects == nil || s.Bootstraps == nil || s.Audit == nil || s.Now == nil || !s.Policy.Valid() || stage == nil || ctx == nil {
		return zero, value.ErrUnavailable
	}
	if !r.Valid() || len(key) != ed25519.PublicKeySize || ClusterBootstrapKeyDigest(key) != r.KeyDigest {
		return zero, value.ErrDenied
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	// A replay of an activated bootstrap returns the original result, also
	// after expiry; a fenced lineage stays fenced.
	if result, err := s.Bootstraps.Activate(ctx, r.BootstrapID, r.SecretDigest, key); err == nil {
		return result, nil
	} else if errors.Is(err, value.ErrClusterCredentialFenced) {
		return zero, err
	}
	enrollment, err := s.Claims.ClaimConnector(ctx, value.EnrollmentClaim{InstallationID: r.InstallationID, BootstrapID: r.BootstrapID, SecretDigest: r.SecretDigest, PublicKeyDigest: r.KeyDigest})
	if err != nil {
		return zero, err
	}
	b := enrollment.Binding
	if enrollment.BootstrapID != r.BootstrapID || enrollment.PublicKeyDigest != r.KeyDigest || b.InstallationID != r.InstallationID || b.ClusterID != r.ClusterID || b.PeerID != r.PeerID || b.IssuerEpoch != r.IssuerEpoch || b.Role != value.ConnectorPeer {
		return zero, value.ErrDenied
	}
	claimDigest, err := acknowledgeEnrollmentClaim(ctx, s.ClaimAudits, s.ClaimObjects, r.InstallationID, r.BootstrapID, enrollment)
	if err != nil {
		return zero, err
	}
	source, err := stage(ctx, enrollment)
	if err != nil {
		return zero, err
	}
	lineage, err := s.Bootstraps.Reserve(ctx, r.BootstrapID, r.RootID, key, source, s.Policy)
	if err != nil {
		return zero, err
	}
	record := audit.ClusterBootstrap{InstallationID: r.InstallationID, BootstrapID: r.BootstrapID, RootID: r.RootID, ClusterID: r.ClusterID, PeerID: r.PeerID, IssuerEpoch: r.IssuerEpoch, LineageID: lineage,
		KeyDigest: r.KeyDigest, ClaimAuditDigest: claimDigest, SourceUID: source.UID, SourceGeneration: source.Generation, ProtectionDigest: source.ProtectionDigest, ReservedAt: s.Now().UTC().Truncate(time.Microsecond)}
	if !record.Valid() {
		return zero, value.ErrDenied
	}
	receipt, err := s.Audit.WriteClusterBootstrap(ctx, record)
	if err != nil {
		return zero, err
	}
	if !receipt.ValidClusterBootstrap(record) {
		return zero, value.ErrDenied
	}
	if err = s.Bootstraps.Acknowledge(ctx, record, receipt); err != nil {
		return zero, err
	}
	result, err := s.Bootstraps.Activate(ctx, r.BootstrapID, r.SecretDigest, key)
	if err != nil {
		return zero, err
	}
	if result.LineageID != lineage || result.KeyDigest != r.KeyDigest {
		return zero, value.ErrDenied
	}
	return result, nil
}

// ClusterBootstrapKeyDigest is the SHA-256 of the Ed25519 key's
// SubjectPublicKeyInfo, the digest the enrollment claim records.
func ClusterBootstrapKeyDigest(key ed25519.PublicKey) artifact.Digest {
	return artifact.Digest(sha256.Sum256(append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}, key...)))
}
