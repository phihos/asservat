package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type installedRetentionShortening struct {
	admin                                     *pgxpool.Pool
	hub, runner                               kubernetes.Interface
	providers                                 *initialRuntimeNativeProviders
	installation, root, hubCluster, namespace string
	diagnose                                  func()
}

func (s installedRetentionShortening) awaitDecision(t *testing.T, ctx context.Context, location artifact.Location, original, want value.Deadlines, policy meta.ObjectMeta) (int64, value.LifecycleDecision, audit.Receipt) {
	t.Helper()
	for {
		var id, checkpoint string
		var checkpointSequence int64
		var raw, digest, receiptRaw []byte
		var acknowledged, completed pgtype.Timestamptz
		var receiptCurrent bool
		var retained, effective value.Deadlines
		var sequence int64
		installedJourneyReadOnly(t, ctx, s.admin, func(tx pgx.Tx) error {
			err := tx.QueryRow(ctx, `
SELECT d.id::text, d.decision_json, d.decision_digest, d.audit_receipt_json, d.audit_acknowledged_at,
       c.id::text, c.sequence, j.completed_at,
       a.anchor_at, a.expires_at, a.delete_by, a.effective_expires_at, a.effective_delete_by, a.retention_sequence,
       coalesce(public.retention_lifecycle_receipt_current(d.root_id,d.id,d.audit_receipt_json),false)
FROM retention_decision d
JOIN retention_catchup_effect e ON e.decision_id=d.id AND e.attempt_id=d.attempt_id
JOIN retention_checkpoint c ON c.id=e.checkpoint_id AND c.root_id=d.root_id
JOIN retention_catchup j ON j.checkpoint_id=c.id
JOIN custody_attempt a ON a.id=d.attempt_id
WHERE d.root_id=$1 AND d.attempt_id=$2 AND d.sequence=1 AND c.cluster_id=$3`, s.root, location.AttemptID, s.hubCluster).
				Scan(&id, &raw, &digest, &receiptRaw, &acknowledged, &checkpoint, &checkpointSequence, &completed,
					&retained.AnchorAt, &retained.ExpiresAt, &retained.DeleteBy, &effective.ExpiresAt, &effective.DeleteBy, &sequence, &receiptCurrent)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		})
		if id != "" {
			effective.AnchorAt = retained.AnchorAt
			var decision value.LifecycleDecision
			if err := json.Unmarshal(raw, &decision); err != nil {
				t.Fatal("installed shortening: invalid retained lifecycle decision", err)
			}
			encoded, err := json.Marshal(decision)
			sum := sha256.Sum256(encoded)
			if sequence != 1 || !sameRetentionDeadlines(retained, original) || !sameRetentionDeadlines(effective, want) ||
				err != nil || !bytes.Equal(digest, sum[:]) || !decision.Valid() ||
				decision.ID != id || decision.RootID != s.root || decision.Location != location || decision.Sequence != sequence ||
				decision.PolicyRevision.UID != checkpoint || decision.PolicyRevision.Generation != checkpointSequence ||
				!sameRetentionDeadlines(decision.Previous, original) || !sameRetentionDeadlines(decision.Effective, want) ||
				!slices.ContainsFunc(decision.Policies, func(rule artifact.RetentionRule) bool {
					return rule.UID == string(policy.UID) && rule.Generation == policy.Generation
				}) {
				t.Fatal("installed shortening: retained effect or lifecycle decision differs from original attempt and exact policy cutoff")
			}
			if completed.Valid && acknowledged.Valid {
				var receipt audit.Receipt
				if !receiptCurrent || json.Unmarshal(receiptRaw, &receipt) != nil || !receipt.ValidLifecycle(s.root, id) {
					t.Fatal("installed shortening: missing exact versioned receipt after acknowledgement")
				}
				return checkpointSequence, decision, receipt
			}
		}
		if err := installedJourneyPause(ctx, time.Second); err != nil {
			t.Fatalf("installed shortening: lifecycle catch-up did not finish (effect=%t completed=%t acknowledged=%t): %v", id != "", completed.Valid, acknowledged.Valid, err)
		}
	}
}

func sameRetentionDeadlines(a, b value.Deadlines) bool {
	return a.AnchorAt.Equal(b.AnchorAt) && a.ExpiresAt.Equal(b.ExpiresAt) && a.DeleteBy.Equal(b.DeleteBy)
}

func readInstalledAuditObject(t *testing.T, ctx context.Context, store *s3.Client, bucket string, receipt audit.Receipt) []byte {
	t.Helper()
	object, err := store.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &receipt.Key, VersionId: &receipt.Version, IfMatch: &receipt.ETag})
	if err != nil {
		t.Fatal("installed audit: acknowledged version unavailable", err)
	}
	defer object.Body.Close()
	ciphertext, err := io.ReadAll(io.LimitReader(object.Body, receipt.Bytes+1))
	if err != nil || int64(len(ciphertext)) != receipt.Bytes || aws.ToString(object.VersionId) != receipt.Version ||
		aws.ToString(object.ETag) != receipt.ETag || sha256.Sum256(ciphertext) != receipt.SHA256 {
		t.Fatal("installed audit: ciphertext differs from its acknowledged version", err)
	}
	return ciphertext
}
