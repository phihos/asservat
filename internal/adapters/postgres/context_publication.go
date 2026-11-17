package postgres

import (
	"bytes"
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ContextPublications struct {
	ledger *Ledger
	root   string
}

var _ authorizationapp.AudienceReader = (*ContextPublications)(nil)

// NewContextPublications reads published catalog rows with SELECT-only credentials.
func NewContextPublications(ctx context.Context, pool *pgxpool.Pool, root string) (*ContextPublications, error) {
	if !authorization.UUID(root) {
		return nil, artifact.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if why := schemaCompatible(ctx, pool); why != "" {
		return nil, schemaRefusal(privacy.ErrUnavailable, why)
	}
	return &ContextPublications{ledger: l, root: root}, nil
}

// historicalPublication checks original durable structure without conferring
// current start, publication or disclosure authority. Progress and historical
// audit reconstruction retain this path after receipt-version policy changes.
func historicalPublication(row custodydb.ContextCapture) (artifact.ContextExpectation, error) {
	accepted, err := admittedRecord(row)
	if err != nil {
		return artifact.ContextExpectation{}, err
	}
	if _, err = captureIntent(row); err != nil || !accepted.Expectation.ServedClass() {
		return artifact.ContextExpectation{}, privacy.ErrFence
	}
	return storedSnapshotProjection(accepted.Expectation, row.SnapshotCoverage, row.SnapshotCoverageDigest, row.SnapshotExpectationDigest)
}

// publishStored is the one publication step (REQ-EVD-001): in the
// transaction that records the collector's stored outcome it stores the copy
// receipts, inserts the catalog row from the admitted expectation plus the
// collector-reported copy digest and native facts, and records the custody
// event. The catalog INSERT triggers add the case/occurrence association,
// capture-time shares and the progress notification. A retry finds the row.
// The caller holds the allocation, attempt and capture locks in that order.
func publishStored(ctx context.Context, q *custodydb.Queries, p custodydb.CustodyPool, allocation custodydb.CustodyAllocation, attempt custodydb.CustodyAttempt, c custodydb.ContextCapture, e artifact.ContextExpectation, w artifact.ContextWriterCompletion) error {
	copies := w.Copies
	if copies.Validate(e.Registration) != nil || !bytes.Equal(attempt.RequestDigest, digest(normalized(e.Registration))) || c.AttemptID != attempt.ID || w.NativeBytes < 0 || w.NativeBytes > e.Registration.NativeLimit || (e.Profile != nil) != (w.Acquisition != nil) || w.Acquisition != nil && !acquisitionMatchesExpectation(e, w.Acquisition) {
		return privacy.ErrConflict
	}
	if err := current(ctx, q, p, allocation, e.Registration, attempt.EffectiveExpiresAt.Time); err != nil {
		return err
	}
	switch attempt.State {
	case artifact.Reserved:
		for i, r := range copies {
			if err := q.StoreCopy(ctx, custodydb.StoreCopyParams{AttemptID: attempt.ID, Role: int16(i), CiphertextBytes: pgtype.Int8{Int64: r.Bytes, Valid: true}, CiphertextSha256: r.SHA256[:], Etag: pgtype.Text{String: r.ETag, Valid: true}, VersionID: pgtype.Text{String: r.VersionID, Valid: r.VersionID != ""}}); err != nil {
				return err
			}
		}
		if err := q.MarkStored(ctx, custodydb.MarkStoredParams{ID: attempt.ID, CopiesDigest: digest(copies)}); err != nil {
			return err
		}
		if err := q.InsertEvent(ctx, custodydb.InsertEventParams{AttemptID: attempt.ID, Phase: "stored"}); err != nil {
			return err
		}
	case artifact.StoredUnpublished:
		if !bytes.Equal(attempt.CopiesDigest, digest(copies)) {
			return privacy.ErrConflict
		}
	default:
		return privacy.ErrExpired
	}
	params := custodydb.InsertContextCatalogParams{ArtifactID: id(e.Registration.Location.ArtifactID), CaptureID: c.ID, RootID: c.RootID, CopiesDigest: digest(copies), NativeBytes: pgtype.Int8{Int64: w.NativeBytes, Valid: true}}
	if w.Acquisition != nil {
		params.AcquisitionStartedAt, params.AcquisitionCompletedAt = ts(w.Acquisition.StartedAt), ts(w.Acquisition.CompletedAt)
	}
	row, err := q.ReadContextCatalog(ctx, custodydb.ReadContextCatalogParams{CaptureID: c.ID, RootID: c.RootID})
	if errors.Is(err, pgx.ErrNoRows) {
		row, err = q.InsertContextCatalog(ctx, params)
	}
	if err != nil {
		return err
	}
	if row.ArtifactID != params.ArtifactID || !bytes.Equal(row.CopiesDigest, params.CopiesDigest) {
		return privacy.ErrConflict
	}
	if attempt.State != artifact.Reserved {
		return nil // a retry found the published row and its audit row
	}
	// ADR-330 D6: the publication's audit row commits with the catalog row,
	// attributed to the capture's requester.
	intent, err := captureIntent(c)
	if err != nil {
		return err
	}
	return InsertAuditEvent(ctx, q, audit.Event{ID: uuid.NewString(), OperationID: e.CaptureUID, Kind: "capture.publish", Operation: "publish_capture", Actor: intent.Requester(), Status: "success", Effect: "published", CaseIDs: []string{e.CaseID}, ArtifactIDs: []string{e.Registration.Location.ArtifactID}, CaptureIDs: []string{e.CaptureUID}, OutputBytes: w.NativeBytes})
}
func (s *ContextPublications) RetainedAudience(ctx context.Context, artifactID string) (authorization.Retained, error) {
	var out authorization.Retained
	if !authorization.UUID(artifactID) {
		return out, artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	row, err := custodydb.New(s.ledger.pool).ReadPublishedContext(ctx, custodydb.ReadPublishedContextParams{ArtifactID: id(artifactID), RootID: id(s.root)})
	if err != nil {
		return out, privacy.ErrUnavailable
	}
	e, err := currentPublishedContext(row)
	if err != nil || e.Registration.Location.ArtifactID != artifactID {
		return out, privacy.ErrUnavailable
	}
	// Ordinary identity, current rights/denies and scope checks precede this
	// lookup and are repeated by the consumer after it. This is not disclosure.
	out = authorization.Retained{ArtifactID: artifactID, Target: authorization.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}, DataClass: e.DataClass, ExpiresAt: row.EffectiveExpiresAt.Time, Audience: e.Audience}
	return out, nil
}

// ContextDownloadEvidence supplies only committed provenance to the ordinary
// download authorizer. It grants no byte access and has SELECT-only credentials.
func (s *ContextPublications) ContextDownloadEvidence(ctx context.Context, artifactID string) (authorizationapp.ContextDownloadEvidence, error) {
	var out authorizationapp.ContextDownloadEvidence
	if !authorization.UUID(artifactID) {
		return out, artifact.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		started, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		row, err := q.ReadPublishedContext(ctx, custodydb.ReadPublishedContextParams{ArtifactID: id(artifactID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		capture := row.ContextCapture
		e, err := currentPublishedContext(row)
		if err != nil {
			return err
		}
		if e.Registration.Location.ArtifactID != artifactID {
			return privacy.ErrFence
		}
		attempt, err := q.ReadAttempt(ctx, capture.AttemptID)
		if err != nil {
			return err
		}
		if attempt.State != artifact.StoredUnpublished || !bytes.Equal(attempt.CopiesDigest, row.ContextCatalog.CopiesDigest) {
			return privacy.ErrFence
		}
		retained, err := retainedContextOrigins(ctx, q, s.root, capture, attempt)
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		until := identity.Earlier(started.Time.Add(5*time.Second), retained.Effective.ExpiresAt)
		if !identity.Fresh(started.Time, until, now.Time, 5*time.Second) {
			return privacy.ErrExpired
		}
		out = authorizationapp.ContextDownloadEvidence{ExecutionDigest: e.PlanDigest, Namespace: e.Namespace, CaptureID: e.CaptureUID, CaseID: e.CaseID, NativeType: e.NativeType, DataClass: e.DataClass, ActionID: e.ActionID, PurposeRef: e.PurposeRef, Audience: e.Audience, Retained: retained, ObservedAt: started.Time, ValidUntil: until}
		labels, labelErr := requestRecordScope(capture)
		if labelErr != nil {
			return labelErr
		}
		out.WorkloadKind, out.WorkloadName, out.PodName = labels.WorkloadKind, labels.WorkloadName, labels.PodName
		if row.ContextCatalog.NativeBytes.Valid {
			size := row.ContextCatalog.NativeBytes.Int64
			out.NativeBytes = &size
		}
		copy(out.Version[:], row.ContextCatalog.CopiesDigest)
		if e.Profile != nil {
			window, err := catalogAcquisition(e, row.ContextCatalog.AcquisitionStartedAt, row.ContextCatalog.AcquisitionCompletedAt)
			if err != nil {
				return err
			}
			out.ProfileAcquisition = &artifact.ProfileAcquisitionMetadata{Type: e.Profile.Type, Mode: e.Profile.Mode, DurationMillis: e.Profile.DurationMillis, ForceGC: e.Profile.ForceGC, Acquisition: window}
		}
		return nil
	})
	if err != nil {
		return authorizationapp.ContextDownloadEvidence{}, err
	}
	return out, nil
}
