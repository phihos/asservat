package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"

	"asservat.local/asservat/internal/application/planning"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CaptureIntents reads an accepted capture's provenance back from its SQL
// row. It cannot start acquisition or disclose this provenance publicly.
type CaptureIntents struct {
	ledger *Ledger
	root   string
}

func NewCaptureIntents(ctx context.Context, pool *pgxpool.Pool, root string) (*CaptureIntents, error) {
	if !authorization.UUID(root) {
		return nil, capture.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, capture.ErrUnavailable
	}
	return &CaptureIntents{l, root}, nil
}

func (s *CaptureIntents) AcceptedCaptureIntent(ctx context.Context, captureID string) (audit.CaptureIntent, error) {
	var out audit.CaptureIntent
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(captureID) {
		return out, capture.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.ReadExactCaptureIntent(ctx, custodydb.ReadExactCaptureIntentParams{RootID: id(s.root), ID: id(captureID)})
		if err != nil {
			return err
		}
		out, err = captureIntent(row)
		return err
	})
	if err != nil || ctx.Err() != nil {
		return audit.CaptureIntent{}, capture.ErrUnavailable
	}
	return out, nil
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
	if b := e.CompositionGroup; b != nil {
		// ADR-276: a composition child's place comes from its own digest-bound
		// expectation; the row's membership must agree.
		if !b.Valid() || !row.GroupID.Valid || !row.GroupOrdinal.Valid || uid(row.GroupID) != b.ParentCaptureID || int(row.GroupOrdinal.Int16) != b.ChildIndex || out.Group != nil {
			return audit.CaptureIntent{}, capture.ErrUnavailable
		}
		out.Group = &audit.CaptureGroupBinding{ParentCaptureID: b.ParentCaptureID, SelectionDigest: out.ScopeDigest, ChildIndex: b.ChildIndex, ChildCount: b.ChildCount}
	} else if row.GroupID.Valid && out.Group == nil {
		return audit.CaptureIntent{}, capture.ErrUnavailable
	}
	copy(out.IdentityRevision.Digest[:], row.IdentityPolicyDigest)
	copy(out.ExpectationDigest[:], digest(e))
	if !out.Valid() {
		return audit.CaptureIntent{}, capture.ErrUnavailable
	}
	return out, nil
}

// captureIntentDigest binds verification and execution records to the
// accepted capture's provenance. It is nil for a malformed row.
func captureIntentDigest(row custodydb.ContextCapture) []byte {
	intent, err := captureIntent(row)
	if err != nil {
		return nil
	}
	return digest(intent)
}
