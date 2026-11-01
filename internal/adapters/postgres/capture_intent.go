package postgres

import (
	"asservat.local/asservat/internal/application/planning"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CaptureIntentAudits struct {
	ledger *Ledger
	root   string
}

var _ auditapp.CaptureIntentLedger = (*CaptureIntentAudits)(nil)
var _ auditapp.ExactCaptureIntentReader = (*CaptureIntentAudits)(nil)

// ReadCaptureIntent observes one accepted row under the audit reader credential.
// It cannot acknowledge a receipt, start acquisition, or disclose this private
// provenance publicly. Unlike the pending page it cannot select another capture.
func (s *CaptureIntentAudits) ReadCaptureIntent(ctx context.Context, captureID string) (auditapp.CaptureIntentSnapshot, error) {
	var out auditapp.CaptureIntentSnapshot
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(captureID) {
		return out, capture.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.ReadExactCaptureIntent(ctx, custodydb.ReadExactCaptureIntentParams{RootID: id(s.root), ID: id(captureID)})
		if err != nil {
			return err
		}
		out, err = exactCaptureIntent(row)
		return err
	})
	if err != nil || ctx.Err() != nil {
		return auditapp.CaptureIntentSnapshot{}, capture.ErrUnavailable
	}
	return out, nil
}

func exactCaptureIntent(row custodydb.ContextCapture) (auditapp.CaptureIntentSnapshot, error) {
	var out auditapp.CaptureIntentSnapshot
	if row.IntentOperationID.Valid {
		return out, capture.ErrUnavailable
	}
	r, err := captureIntent(row)
	if err != nil {
		return out, err
	}
	out.Intent = r
	if !row.IntentAcknowledgedAt.Valid {
		if row.State != capture.PendingAudit || row.IntentDigest != nil || row.IntentObjectKey.Valid || row.IntentObjectVersion.Valid || row.IntentObjectEtag.Valid || row.IntentObjectBytes.Valid || row.IntentObjectSha256 != nil {
			return auditapp.CaptureIntentSnapshot{}, capture.ErrUnavailable
		}
		return out, nil
	}
	receipt := audit.Receipt{Key: row.IntentObjectKey.String, Version: row.IntentObjectVersion.String, ETag: row.IntentObjectEtag.String, Bytes: row.IntentObjectBytes.Int64}
	copy(receipt.SHA256[:], row.IntentObjectSha256)
	if row.State != capture.IntentAudited || !bytes.Equal(row.IntentDigest, digest(r)) || !row.IntentObjectKey.Valid || !row.IntentObjectVersion.Valid || !row.IntentObjectEtag.Valid || !row.IntentObjectBytes.Valid || len(row.IntentObjectSha256) != 32 || !receipt.ValidCaptureIntent(r.RootID, r.CaptureID) {
		return auditapp.CaptureIntentSnapshot{}, capture.ErrUnavailable
	}
	out.Receipt = &receipt
	return out, nil
}

func NewCaptureIntentAudits(ctx context.Context, pool *pgxpool.Pool, root string) (*CaptureIntentAudits, error) {
	if !authorization.UUID(root) {
		return nil, capture.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, capture.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if why := schemaCompatible(ctx, pool); why != "" {
		return nil, schemaRefusal(capture.ErrUnavailable, why)
	}
	return &CaptureIntentAudits{l, root}, nil
}

func captureIntent(row custodydb.ContextCapture) (audit.CaptureIntent, error) {
	var out audit.CaptureIntent
	accepted, err := admittedRecord(row)
	if err != nil {
		return out, err
	}
	d := sha256.Sum256(row.ScopeJson)
	if !bytes.Equal(d[:], row.ScopeDigest) {
		return out, capture.ErrUnavailable
	}
	var scope struct {
		Executor struct {
			Issuer   string        `json:"issuer"`
			Subject  string        `json:"subject"`
			ClientID string        `json:"clientID"`
			Kind     identity.Kind `json:"identityType"`
		} `json:"executor"`
	}
	if json.Unmarshal(row.ScopeJson, &scope) != nil {
		return out, capture.ErrUnavailable
	}
	e := accepted.Expectation
	out = audit.CaptureIntent{RootID: uid(row.RootID), CaptureID: accepted.CaptureID, CaseID: e.CaseID, OccurrenceID: e.OccurrenceID, ArtifactID: e.Registration.Location.ArtifactID, AttemptID: e.Registration.Location.AttemptID, Actor: identity.Principal{Issuer: scope.Executor.Issuer, Subject: scope.Executor.Subject, ClientID: scope.Executor.ClientID, Kind: scope.Executor.Kind}, Target: authorization.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}, ScopeDigest: accepted.ScopeDigest, SubmissionDigest: accepted.SubmissionDigest, PermissionEpoch: uid(row.PermissionEpoch), PermissionSequence: row.PermissionSequence, IdentityRevision: identity.Revision{UID: row.IdentityPolicyUid, Generation: row.IdentityPolicyGeneration}, CreatedAt: accepted.CreatedAt, Deadline: accepted.Deadline, ExpiresAt: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy, ReservedBytes: e.Registration.ReservedBytes()}
	if e.Snapshot != nil && e.Lifecycle != nil && e.Lifecycle.TriggerKind == "recordingSave" {
		parsed, err := planning.ReadContextScopeIdentity(row.ScopeJson, out.ScopeDigest)
		if err != nil || parsed.Requester == nil || parsed.Actor != out.Actor {
			return out, capture.ErrUnavailable
		}
		initiator := *parsed.Requester
		out.Initiator = &initiator
		if row.GroupID.Valid {
			if !row.GroupOrdinal.Valid || uid(row.GroupID) != parsed.CaptureID || len(parsed.Targets) < 2 || int(row.GroupOrdinal.Int16) >= len(parsed.Targets) || row.GroupOrdinal.Int16 < 0 || parsed.Targets[row.GroupOrdinal.Int16] != out.Target {
				return audit.CaptureIntent{}, capture.ErrUnavailable
			}
			out.Group = &audit.CaptureGroupBinding{ParentCaptureID: uid(row.GroupID), SelectionDigest: out.ScopeDigest, ChildIndex: int(row.GroupOrdinal.Int16), ChildCount: len(parsed.Targets)}
		} else if len(parsed.Targets) > 1 {
			return audit.CaptureIntent{}, capture.ErrUnavailable
		}
	}
	copy(out.IdentityRevision.Digest[:], row.IdentityPolicyDigest)
	copy(out.ExpectationDigest[:], digest(e))
	if row.ReasonRef != nil {
		var ref audit.CaptureReasonRef
		d := json.NewDecoder(bytes.NewReader(row.ReasonRef))
		d.DisallowUnknownFields()
		if d.Decode(&ref) != nil || !ref.Valid() {
			return out, capture.ErrUnavailable
		}
		out.ReasonRef = &ref
	}
	if !out.Valid() {
		return audit.CaptureIntent{}, capture.ErrUnavailable
	}
	return out, nil
}
func (s *CaptureIntentAudits) PendingCaptureIntents(ctx context.Context) ([]audit.CaptureIntent, error) {
	var out []audit.CaptureIntent
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.PendingCaptureIntents(ctx, id(s.root))
		if err != nil {
			return err
		}
		out = nil
		for _, row := range rows {
			r, err := captureIntent(row)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, captureError(err)
	}
	return out, nil
}
func (s *CaptureIntentAudits) AcknowledgeCaptureIntent(ctx context.Context, r audit.CaptureIntent, receipt audit.Receipt) error {
	if r.RootID != s.root || !r.Valid() || !receipt.ValidCaptureIntent(r.RootID, r.CaptureID) {
		return capture.ErrInvalid
	}
	return captureError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		// Audit acknowledgement survives revocation/expiry, so the intent remains
		// explainable. It never renews authority, deadlines or storage reservations.
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		row, err := q.LockContextCapture(ctx, custodydb.LockContextCaptureParams{ID: id(r.CaptureID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		if row.IntentOperationID.Valid {
			return capture.ErrUnavailable
		}
		frozen, err := captureIntent(row)
		if err != nil {
			return err
		}
		if !bytes.Equal(digest(frozen), digest(r)) {
			return capture.ErrChanged
		}
		if row.IntentAcknowledgedAt.Valid {
			if !bytes.Equal(row.IntentDigest, digest(r)) || row.IntentObjectKey.String != receipt.Key || row.IntentObjectVersion.String != receipt.Version || row.IntentObjectEtag.String != receipt.ETag || row.IntentObjectBytes.Int64 != receipt.Bytes || !bytes.Equal(row.IntentObjectSha256, receipt.SHA256[:]) {
				return capture.ErrChanged
			}
			return nil
		}
		changed, err := q.AcknowledgeCaptureIntent(ctx, custodydb.AcknowledgeCaptureIntentParams{ID: row.ID, IntentDigest: digest(r), IntentObjectKey: pgtype.Text{String: receipt.Key, Valid: true}, IntentObjectVersion: pgtype.Text{String: receipt.Version, Valid: true}, IntentObjectEtag: pgtype.Text{String: receipt.ETag, Valid: true}, IntentObjectBytes: pgtype.Int8{Int64: receipt.Bytes, Valid: true}, IntentObjectSha256: receipt.SHA256[:]})
		if err != nil {
			return err
		}
		if changed != 1 {
			return capture.ErrChanged
		}
		return nil
	}))
}
