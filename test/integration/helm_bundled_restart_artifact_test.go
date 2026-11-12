package integration

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Only the exact published artifact is compared. Source observations, account
// totals and background audit work may legitimately advance during a restart.
type bundledRestartArtifact struct {
	RootID, CaseID, ArtifactID, CaptureID, AttemptID, AllocationID string
	ClusterID, NamespaceUID, WorkloadUID, PodUID, ExecutionObject  string
	WriterInstallation, WriterEpoch                                string
	PoolRevision, AllocationRevision, NativeLimit, ReservedBytes   int64
	RetentionSequence, ChargedBytes, ChargedObjects                int64
	WriterDatabaseOID                                              uint32
	CreatedAt, Deadline, AnchorAt, WriteUntil                      time.Time
	OriginalExpiresAt, OriginalDeleteBy, ExpiresAt, DeleteBy       time.Time
	StartNotBefore, StartNotAfter, StartedAt, AcquiredAt           time.Time
	CompletedAt, WriterPostmaster, WriterStoredAt, WriterClosedAt  time.Time
	PublishedAt, VerifiedAt, VerificationAuditAt                   time.Time
	Copies                                                         [4]bundledRestartCopy
}

type bundledRestartCopy struct {
	Role              int32
	Limit, Ciphertext int64
}

func readBundledRestartArtifact(t *testing.T, ctx context.Context, sql *pgxpool.Pool, root, caseID, artifactID string) bundledRestartArtifact {
	t.Helper()
	if ctx == nil || sql == nil || ctx.Err() != nil {
		t.Fatal("bundled restart: original bounded observation unavailable")
	}
	if until, bounded := ctx.Deadline(); !bounded || !time.Now().Before(until) {
		t.Fatal("bundled restart: original bounded observation unavailable")
	}
	s := bundledRestartArtifact{RootID: root, CaseID: caseID, ArtifactID: artifactID}
	var observed time.Time
	var control, completed, acknowledged bool
	var roles []int32
	var limits, sizes []int64
	// The relative-charge expression is the existing fixed pod-status deletion
	// proof: another capture in this allocation may be independently deleted.
	err := sql.QueryRow(ctx, bundledRestartArtifactSQL, root, caseID, artifactID).Scan(
		&observed, &s.CaptureID, &s.AttemptID, &s.AllocationID,
		&s.ClusterID, &s.NamespaceUID, &s.WorkloadUID, &s.PodUID, &s.ExecutionObject,
		&s.PoolRevision, &s.AllocationRevision, &s.NativeLimit, &s.ReservedBytes,
		&s.RetentionSequence, &s.CreatedAt, &s.Deadline,
		&s.AnchorAt, &s.WriteUntil, &s.OriginalExpiresAt, &s.OriginalDeleteBy,
		&s.ExpiresAt, &s.DeleteBy, &s.StartNotBefore, &s.StartNotAfter,
		&s.StartedAt, &s.AcquiredAt, &s.CompletedAt,
		&s.WriterInstallation, &s.WriterEpoch, &s.WriterPostmaster, &s.WriterDatabaseOID,
		&s.WriterStoredAt, &s.WriterClosedAt, &s.PublishedAt, &s.VerifiedAt,
		&s.VerificationAuditAt, &completed, &acknowledged,
		&s.ChargedBytes, &s.ChargedObjects, &control, &roles, &limits, &sizes)
	if err != nil || ctx.Err() != nil || !observed.Before(s.ExpiresAt) || !control || !completed || !acknowledged ||
		s.ReservedBytes <= 0 || s.ChargedBytes != s.ReservedBytes || s.ChargedObjects != 4 ||
		!slices.Equal(roles, []int32{0, 1, 2, 3}) || len(limits) != 4 || len(sizes) != 4 {
		t.Fatal("bundled restart: original published artifact or exact charges unavailable")
	}
	for i := range s.Copies {
		if sizes[i] <= 0 || sizes[i] > limits[i] {
			t.Fatal("bundled restart: original completed ciphertext copy unavailable")
		}
		s.Copies[i] = bundledRestartCopy{Role: roles[i], Limit: limits[i], Ciphertext: sizes[i]}
	}
	// SQL instants have no monotonic component; normalize their location so the
	// scalar comparison cannot confuse a timezone representation with renewal.
	for _, at := range []*time.Time{&s.CreatedAt, &s.Deadline, &s.AnchorAt, &s.WriteUntil,
		&s.OriginalExpiresAt, &s.OriginalDeleteBy, &s.ExpiresAt, &s.DeleteBy,
		&s.StartNotBefore, &s.StartNotAfter, &s.StartedAt, &s.AcquiredAt, &s.CompletedAt,
		&s.WriterPostmaster, &s.WriterStoredAt, &s.WriterClosedAt, &s.PublishedAt,
		&s.VerifiedAt, &s.VerificationAuditAt} {
		*at = at.UTC()
	}
	return s
}

func compareBundledRestartArtifact(t *testing.T, before, after bundledRestartArtifact) {
	t.Helper()
	if before != after {
		// Never dump the snapshot or provider error into an installed result log.
		t.Fatal("bundled restart: original artifact identity, cutoffs, completion or charges changed")
	}
}

// Shared with the real-server, missing-row SQL shape preflight.
const bundledRestartArtifactSQL = `
SELECT clock_timestamp(), l.capture_id::text, c.attempt_id::text,
       a.allocation_id::text, l.cluster_id::text, l.namespace_uid,
       l.workload_uid, l.pod_uid, e.object_uid::text,
       a.pool_revision, a.allocation_revision, a.native_limit, a.reserved_bytes,
       a.retention_sequence, c.created_at, c.deadline,
       a.anchor_at, a.write_until, a.expires_at, a.delete_by,
       a.effective_expires_at, a.effective_delete_by,
       e.not_before, e.not_after, e.started_at, e.acquired_at, e.completed_at,
       w.installation_id::text, w.issuer_epoch::text, w.postmaster_at,
       w.database_oid, w.stored_at, w.closed_at,
       cat.published_at, v.verified_at, v.audit_acknowledged_at,
       octet_length(w.completion_digest)=32,
       v.audit_object_bytes>0 AND v.audit_object_version<>''
         AND v.audit_object_etag<>'' AND v.audit_object_sha256 IS NOT NULL,
       ca.charged_bytes-(SELECT coalesce(sum(x.reserved_bytes),0)
         FROM custody_attempt x WHERE x.allocation_id=a.allocation_id
         AND x.id<>a.id AND x.state<>'deleted'),
       ca.charged_objects-4*(SELECT count(*) FROM custody_attempt x
         WHERE x.allocation_id=a.allocation_id AND x.id<>a.id AND x.state<>'deleted'),
       EXISTS(SELECT 1 FROM context_control_charge ch
         WHERE ch.root_id=c.root_id AND ch.capture_id=c.id
         AND ch.allocation_id=a.allocation_id),
       (SELECT array_agg(cp.role::integer ORDER BY cp.role)
         FROM custody_copy cp WHERE cp.attempt_id=a.id),
       (SELECT array_agg(cp.byte_limit ORDER BY cp.role)
         FROM custody_copy cp WHERE cp.attempt_id=a.id),
       (SELECT array_agg(cp.ciphertext_bytes ORDER BY cp.role)
         FROM custody_copy cp WHERE cp.attempt_id=a.id)
FROM context_case_locator l
JOIN context_capture c ON c.root_id=l.root_id AND c.id=l.capture_id
JOIN custody_attempt a ON a.id=c.attempt_id AND a.artifact_id=l.artifact_id
  AND a.cluster_id=l.cluster_id
JOIN custody_allocation ca ON ca.id=a.allocation_id
JOIN context_execution e ON e.root_id=c.root_id AND e.capture_id=c.id AND e.attempt_id=a.id
JOIN context_writer_completion w ON w.root_id=c.root_id AND w.capture_id=c.id AND w.attempt_id=a.id
JOIN context_catalog cat ON cat.root_id=c.root_id AND cat.capture_id=c.id AND cat.artifact_id=a.artifact_id
JOIN context_verification v ON v.root_id=c.root_id AND v.capture_id=c.id
WHERE l.root_id=$1 AND l.case_id=$2 AND l.artifact_id=$3
  AND c.state='intent_audited' AND a.state='stored_unpublished'
  AND e.phase='stored' AND v.audit_acknowledged_at IS NOT NULL`
