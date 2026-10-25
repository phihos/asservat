package postgres

import (
	executionapp "asservat.local/asservat/internal/application/execution"
	executionvalue "asservat.local/asservat/internal/domain/execution"
	"bytes"
	"context"
	"errors"
	"reflect"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	privacyvalue "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ContextPublications struct {
	ledger    *Ledger
	root      string
	retention *RetentionTransactionGuard
	recovery  *RecoveryTransactionGuard
}

var _ evidence.ContextPublicationLedger = (*ContextPublications)(nil)
var _ authorizationapp.AudienceReader = (*ContextPublications)(nil)

// Instantiate each facet with separate verification, audit, publish or SELECT
// credentials. Sharing a Go implementation does not combine runtime SQL roles.
func NewContextPublications(ctx context.Context, pool *pgxpool.Pool, root string, guards ...EffectTransactionGuards) (*ContextPublications, error) {
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
	guard, err := effectGuardsFor(root, guards)
	if err != nil {
		return nil, err
	}
	return &ContextPublications{ledger: l, root: root, retention: guard.Retention, recovery: guard.Recovery}, nil
}

// historicalPublication checks original durable structure without conferring
// current start, publication or disclosure authority. Progress and historical
// audit reconstruction retain this path after receipt-version policy changes.
func historicalPublication(row custodydb.ContextCapture) (artifact.ContextExpectation, error) {
	accepted, err := admittedRecord(row)
	if err != nil {
		return artifact.ContextExpectation{}, err
	}
	intent, err := captureIntent(row)
	if err != nil || row.State != capture.IntentAudited || !row.IntentAcknowledgedAt.Valid || !bytes.Equal(row.IntentDigest, digest(intent)) || accepted.Expectation.DataClass != "metadata" {
		return artifact.ContextExpectation{}, privacy.ErrFence
	}
	return accepted.Expectation, nil
}
func (s *ContextPublications) AcceptedContextForPublication(ctx context.Context, captureID string) (artifact.ContextExpectation, error) {
	var out artifact.ContextExpectation
	if !authorization.UUID(captureID) {
		return out, artifact.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.ReadPublicationCapture(ctx, custodydb.ReadPublicationCaptureParams{ID: id(captureID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		out, err = acceptedPublication(row)
		return err
	})
	return out, err
}
func (s *ContextPublications) publicationFence(ctx context.Context, q *custodydb.Queries, stream custodydb.PermissionStream, e artifact.ContextExpectation, a artifact.PublicationAuthority, topology privacyvalue.PolicyTopology, recovery custodydb.FleetCurrentTrust) error {
	if err := s.recovery.check(ctx, q, recovery, s.root, a.Recovery); err != nil {
		return err
	}
	if err := s.retention.check(ctx, q, topology, a.Retention, authorization.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}); err != nil {
		return err
	}
	n, err := q.CurrentTime(ctx)
	if err != nil {
		return err
	}
	if !a.Valid(e, evidence.ContextExpectationDigest(e), n.Time) || stream.ID != id(a.RootID) || stream.Epoch != id(a.PermissionEpoch) || stream.Sequence != a.PermissionSequence || !bytes.Equal(stream.ProjectionDigest, a.ProjectionDigest[:]) || stream.Suspended || !stream.InitialAuditID.Valid || !n.Time.Before(stream.LeaseUntil.Time) || !identity.Fresh(stream.ObservedAt.Time, stream.FreshUntil.Time, n.Time, authorization.PermissionObservationInterval) {
		return privacy.ErrFence
	}
	for _, auditID := range []pgtype.UUID{stream.Epoch, stream.InitialAuditID} {
		r, err := q.ReadAuthorityAudit(ctx, auditID)
		if err != nil {
			return err
		}
		if !currentAuthorityAudit(r, stream.ID, auditID) {
			return privacy.ErrFence
		}
	}
	return s.recovery.check(ctx, q, recovery, s.root, a.Recovery)
}

// Canonical order: recovery root -> permission root -> storage pool/allocation -> attempt ->
// capture -> verification/catalog. No external work occurs while locks are held.
func (s *ContextPublications) publicationLocks(ctx context.Context, q *custodydb.Queries, e artifact.ContextExpectation, c artifact.Copies, a artifact.PublicationAuthority, topology privacyvalue.PolicyTopology, recovery custodydb.FleetCurrentTrust) (custodydb.PermissionStream, custodydb.CustodyPool, custodydb.CustodyAllocation, custodydb.CustodyAttempt, custodydb.ContextCapture, error) {
	var stream custodydb.PermissionStream
	var pool custodydb.CustodyPool
	var allocation custodydb.CustodyAllocation
	var attempt custodydb.CustodyAttempt
	var accepted custodydb.ContextCapture
	stream, err := q.LockPermissionStream(ctx, id(s.root))
	if err != nil {
		return stream, pool, allocation, attempt, accepted, err
	}
	pool, allocation, err = lockAllocation(ctx, q, e.Registration.AllocationID)
	if err != nil {
		return stream, pool, allocation, attempt, accepted, err
	}
	attempt, err = q.LockAttempt(ctx, id(e.Registration.Location.AttemptID))
	if err != nil {
		return stream, pool, allocation, attempt, accepted, err
	}
	accepted, err = q.LockContextCapture(ctx, custodydb.LockContextCaptureParams{ID: id(e.CaptureUID), RootID: id(s.root)})
	if err != nil {
		return stream, pool, allocation, attempt, accepted, err
	}
	expected, err := acceptedPublication(accepted)
	if err == nil && (!bytes.Equal(digest(expected), digest(e)) || !bytes.Equal(attempt.RequestDigest, digest(normalized(e.Registration))) || accepted.AttemptID != attempt.ID || c.Validate(e.Registration) != nil || (attempt.State != artifact.Reserved && attempt.State != artifact.StoredUnpublished)) {
		err = privacy.ErrConflict
	}
	if err == nil && e.ExecutionClass == artifact.ContextAPIExecution {
		row, readErr := q.ReadAPIExecution(ctx, custodydb.ReadAPIExecutionParams{RootID: accepted.RootID, CaptureID: accepted.ID})
		if readErr != nil {
			err = privacy.ErrFence
		} else {
			x, decodeErr := apiExecution(row)
			if decodeErr != nil || !validCompletedAPI(x, e) || !reflect.DeepEqual(x.Copies, c) || executionapp.APIExecutionDigest(x) != a.AuthorityDigest {
				err = privacy.ErrFence
			}
		}
	}
	if err == nil {
		err = current(ctx, q, pool, allocation, e.Registration, attempt.EffectiveExpiresAt.Time)
	}
	if err == nil {
		err = s.publicationFence(ctx, q, stream, e, a, topology, recovery)
	}
	return stream, pool, allocation, attempt, accepted, err
}
func verificationRecord(c custodydb.ContextCapture, v custodydb.ContextVerification, executions ...executionvalue.APIExecution) (audit.ContextVerification, error) {
	e, err := historicalPublication(c)
	if err != nil {
		return audit.ContextVerification{}, err
	}
	r := audit.ContextVerification{RootID: uid(c.RootID), CaptureID: uid(c.ID), ArtifactID: e.Registration.Location.ArtifactID, AttemptID: e.Registration.Location.AttemptID, PermissionEpoch: uid(v.PermissionEpoch), PermissionSequence: v.PermissionSequence, ScopeDigest: e.PlanDigest, VerifiedAt: v.VerifiedAt.Time, WriteUntil: e.Registration.WriteUntil, ExpiresAt: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy}
	for _, pair := range []struct {
		dst *artifact.Digest
		src []byte
	}{{&r.ExpectationDigest, v.ExpectationDigest}, {&r.CopiesDigest, v.CopiesDigest}, {&r.IntentDigest, v.IntentDigest}, {&r.AuthorityDigest, v.AuthorityDigest}} {
		if len(pair.src) != 32 {
			return audit.ContextVerification{}, privacy.ErrUnavailable
		}
		copy(pair.dst[:], pair.src)
	}
	if e.ExecutionClass == artifact.ContextAPIExecution {
		if len(executions) != 1 || !validCompletedAPI(executions[0], e) || executions[0].ExpectationDigest != r.ExpectationDigest || executionapp.APIExecutionDigest(executions[0]) != r.AuthorityDigest || evidence.ContextCopiesDigest(executions[0].Copies) != r.CopiesDigest {
			return audit.ContextVerification{}, privacy.ErrFence
		}
		x := executions[0]
		p := x.Process
		r.APIOutcome = &audit.APIOutcome{InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, ExecutorNamespaceUID: p.NamespaceUID, ExecutorAccountUID: p.AccountUID, ExecutorPodUID: p.PodUID, ProcessEpoch: p.ProcessEpoch, StartObjectUID: x.ObjectUID, ExecutionDigest: r.AuthorityDigest, StartupDigest: p.StartupDigest, StartedAt: x.StartedAt, AcquiredAt: x.AcquiredAt, CompletedAt: x.CompletedAt}
		copy(r.APIOutcome.BindingDigest[:], digest(x.Binding))
	} else if len(executions) > 0 {
		return audit.ContextVerification{}, privacy.ErrFence
	}
	if v.CaptureID != c.ID || v.RootID != c.RootID || r.ExpectationDigest != evidence.ContextExpectationDigest(e) || !bytes.Equal(v.IntentDigest, c.IntentDigest) || !r.Valid() {
		return audit.ContextVerification{}, privacy.ErrConflict
	}
	return r, nil
}
func (s *ContextPublications) RecordContextVerification(ctx context.Context, e artifact.ContextExpectation, c artifact.Copies, a artifact.PublicationAuthority) (audit.ContextVerification, error) {
	var out audit.ContextVerification
	if e.Validate() != nil || c.Validate(e.Registration) != nil || a.RootID != s.root {
		return out, artifact.ErrInvalid
	}
	topology, err := s.retention.observe(ctx, e.Registration.Location.ClusterID)
	if err != nil {
		return out, err
	}
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		recovery, err := s.recovery.lock(ctx, q, s.root, a.Recovery)
		if err != nil {
			return err
		}
		stream, pool, allocation, attempt, accepted, err := s.publicationLocks(ctx, q, e, c, a, topology, recovery)
		if err != nil {
			return err
		}
		if attempt.State == artifact.StoredUnpublished {
			if !bytes.Equal(attempt.CopiesDigest, digest(c)) {
				return privacy.ErrConflict
			}
		} else {
			for i, copy := range c {
				err = q.StoreCopy(ctx, custodydb.StoreCopyParams{AttemptID: attempt.ID, Role: int16(i), CiphertextBytes: pgtype.Int8{Int64: copy.Bytes, Valid: true}, CiphertextSha256: copy.SHA256[:], Etag: pgtype.Text{String: copy.ETag, Valid: true}, VersionID: pgtype.Text{String: copy.VersionID, Valid: copy.VersionID != ""}})
				if err != nil {
					return err
				}
			}
			if err = q.MarkStored(ctx, custodydb.MarkStoredParams{ID: attempt.ID, CopiesDigest: digest(c)}); err != nil {
				return err
			}
			if err = q.InsertEvent(ctx, custodydb.InsertEventParams{AttemptID: attempt.ID, Phase: "stored"}); err != nil {
				return err
			}
		}
		row, err := q.ReadContextVerification(ctx, custodydb.ReadContextVerificationParams{CaptureID: accepted.ID, RootID: accepted.RootID})
		if errors.Is(err, pgx.ErrNoRows) {
			row, err = q.InsertContextVerification(ctx, custodydb.InsertContextVerificationParams{CaptureID: accepted.ID, RootID: accepted.RootID, ExpectationDigest: digest(e), CopiesDigest: digest(c), IntentDigest: accepted.IntentDigest, AuthorityDigest: a.AuthorityDigest[:], PermissionEpoch: id(a.PermissionEpoch), PermissionSequence: a.PermissionSequence})
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(row.CopiesDigest, digest(c)) {
			return privacy.ErrConflict
		}
		out, err = currentVerificationRecord(ctx, q, accepted, row)
		if err != nil {
			return err
		}
		if err = current(ctx, q, pool, allocation, e.Registration, attempt.EffectiveExpiresAt.Time); err != nil {
			return err
		}
		return s.publicationFence(ctx, q, stream, e, a, topology, recovery)
	})
	if err != nil {
		return audit.ContextVerification{}, err
	}
	return out, nil
}
func (s *ContextPublications) AcknowledgeContextVerification(ctx context.Context, r audit.ContextVerification, receipt audit.Receipt) error {
	if r.RootID != s.root || !r.Valid() || !receipt.ValidContextVerification(r.RootID, r.CaptureID) {
		return artifact.ErrInvalid
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		// Historical verified facts may be audited after expiry; no publication,
		// retention extension, refund or new capture follows from this receipt.
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		c, err := q.LockContextCapture(ctx, custodydb.LockContextCaptureParams{ID: id(r.CaptureID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		v, err := q.LockContextVerification(ctx, custodydb.LockContextVerificationParams{CaptureID: c.ID, RootID: c.RootID})
		if err != nil {
			return err
		}
		frozen, err := currentVerificationRecord(ctx, q, c, v)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(frozen, r) {
			return privacy.ErrConflict
		}
		if v.AuditAcknowledgedAt.Valid {
			if !bytes.Equal(v.AuditDigest, digest(r)) || v.AuditObjectKey.String != receipt.Key || v.AuditObjectVersion.String != receipt.Version || v.AuditObjectEtag.String != receipt.ETag || v.AuditObjectBytes.Int64 != receipt.Bytes || !bytes.Equal(v.AuditObjectSha256, receipt.SHA256[:]) {
				return privacy.ErrConflict
			}
			return nil
		}
		count, err := q.AcknowledgeContextVerification(ctx, custodydb.AcknowledgeContextVerificationParams{CaptureID: c.ID, RootID: c.RootID, AuditDigest: digest(r), AuditObjectKey: pgtype.Text{String: receipt.Key, Valid: true}, AuditObjectVersion: pgtype.Text{String: receipt.Version, Valid: true}, AuditObjectEtag: pgtype.Text{String: receipt.ETag, Valid: true}, AuditObjectBytes: pgtype.Int8{Int64: receipt.Bytes, Valid: true}, AuditObjectSha256: receipt.SHA256[:]})
		if err != nil {
			return err
		}
		if count != 1 {
			return privacy.ErrConflict
		}
		return nil
	})
}
func (s *ContextPublications) PublishContext(ctx context.Context, e artifact.ContextExpectation, c artifact.Copies, a artifact.PublicationAuthority) (artifact.PublishedContext, error) {
	var out artifact.PublishedContext
	if e.Validate() != nil || c.Validate(e.Registration) != nil || a.RootID != s.root {
		return out, artifact.ErrInvalid
	}
	topology, err := s.retention.observe(ctx, e.Registration.Location.ClusterID)
	if err != nil {
		return out, err
	}
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		recovery, err := s.recovery.lock(ctx, q, s.root, a.Recovery)
		if err != nil {
			return err
		}
		stream, pool, allocation, attempt, accepted, err := s.publicationLocks(ctx, q, e, c, a, topology, recovery)
		if err != nil {
			return err
		}
		if attempt.State != artifact.StoredUnpublished || !bytes.Equal(attempt.CopiesDigest, digest(c)) {
			return privacy.ErrConflict
		}
		v, err := q.ReadContextVerification(ctx, custodydb.ReadContextVerificationParams{CaptureID: accepted.ID, RootID: accepted.RootID})
		if err != nil {
			return err
		}
		r, err := currentVerificationRecord(ctx, q, accepted, v)
		if err != nil {
			return err
		}
		if !currentVerificationReceipt(v) || !bytes.Equal(v.AuditDigest, digest(r)) || r.CopiesDigest != evidence.ContextCopiesDigest(c) {
			return privacy.ErrFence
		}
		row, err := q.ReadContextCatalog(ctx, custodydb.ReadContextCatalogParams{CaptureID: accepted.ID, RootID: accepted.RootID})
		if errors.Is(err, pgx.ErrNoRows) {
			row, err = q.InsertContextCatalog(ctx, custodydb.InsertContextCatalogParams{ArtifactID: id(e.Registration.Location.ArtifactID), CaptureID: accepted.ID, RootID: accepted.RootID})
		}
		if err != nil {
			return err
		}
		if row.ArtifactID != id(e.Registration.Location.ArtifactID) {
			return privacy.ErrConflict
		}
		out = artifact.PublishedContext{RootID: s.root, CaptureID: e.CaptureUID, Expectation: e, Copies: c, VerifiedAt: v.VerifiedAt.Time, PublishedAt: row.PublishedAt.Time}
		if err = current(ctx, q, pool, allocation, e.Registration, attempt.EffectiveExpiresAt.Time); err != nil {
			return err
		}
		return s.publicationFence(ctx, q, stream, e, a, topology, recovery)
	})
	if err != nil {
		return artifact.PublishedContext{}, err
	}
	return out, nil
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
		if attempt.State != artifact.StoredUnpublished || !bytes.Equal(attempt.CopiesDigest, row.ContextVerification.CopiesDigest) {
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
		out = authorizationapp.ContextDownloadEvidence{CaptureID: e.CaptureUID, PurposeRef: e.PurposeRef, Audience: e.Audience, Retained: retained, ObservedAt: started.Time, ValidUntil: until}
		copy(out.Version[:], row.ContextVerification.CopiesDigest)
		return nil
	})
	if err != nil {
		return authorizationapp.ContextDownloadEvidence{}, err
	}
	return out, nil
}
