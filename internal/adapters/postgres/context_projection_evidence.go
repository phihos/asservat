package postgres

import (
	"bytes"
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

var _ authorizationapp.ContextProjectionCatalog = (*ContextPublications)(nil)

// ContextProjectionEvidence returns the independently verified fixed context
// profile and its original publication identity. The SELECT-only facet provides
// no native content or read permit. C-03 checks ordinary target eligibility
// before calling it, then current audience, retention and query-purpose state.
func (s *ContextPublications) ContextProjectionEvidence(ctx context.Context, artifactID string) (authorizationapp.ContextProjectionEvidence, error) {
	var out authorizationapp.ContextProjectionEvidence
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil {
		return out, analysis.ErrUnavailable
	}
	if !authorization.UUID(artifactID) {
		return out, artifact.ErrInvalid
	}
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	err := s.ledger.transaction(call, func(q *custodydb.Queries) error {
		out = authorizationapp.ContextProjectionEvidence{}
		started, err := q.CurrentTime(call)
		if err != nil {
			return err
		}
		row, err := q.ReadPublishedContext(call, custodydb.ReadPublishedContextParams{ArtifactID: id(artifactID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		e, err := currentPublishedContext(row)
		if err != nil {
			return err
		}
		if e.Registration.Location.ArtifactID != artifactID || e.DataClass != "metadata" || e.Registration.NativeLimit != artifact.MaxContextBytes {
			return privacy.ErrFence
		}
		attempt, err := q.ReadAttempt(call, row.ContextCapture.AttemptID)
		if err != nil {
			return err
		}
		if attempt.State != artifact.StoredUnpublished || !bytes.Equal(attempt.CopiesDigest, row.ContextVerification.CopiesDigest) {
			return privacy.ErrFence
		}
		retained, err := retainedContextOrigins(call, q, s.root, row.ContextCapture, attempt)
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(call)
		if err != nil {
			return err
		}
		until := identity.Earlier(started.Time.Add(5*time.Second), retained.Effective.ExpiresAt)
		if d, ok := call.Deadline(); ok {
			until = identity.Earlier(until, d)
		}
		if !identity.Fresh(started.Time, until, now.Time, 5*time.Second) {
			return privacy.ErrExpired
		}
		// The current context verifier accepts exactly this native format and
		// manifest projection definition. These constants describe that verified
		// profile; they are not a content hash or a substitute for C-14's later
		// independent envelope/manifest/native verification of the pinned bytes.
		out = authorizationapp.ContextProjectionEvidence{
			CaseID: e.CaseID, CaptureID: e.CaptureUID, PurposeRef: e.PurposeRef,
			SourceProjectionDigest: analysis.ContextSourceProjectionDigest(),
			SourceFormat:           artifact.ContextFormat, DataClass: e.DataClass,
			Audience: e.Audience, Retained: retained, ObservedAt: started.Time, ValidUntil: until,
		}
		copy(out.Version[:], row.ContextVerification.CopiesDigest)
		return call.Err()
	})
	if err != nil {
		return authorizationapp.ContextProjectionEvidence{}, err
	}
	if call.Err() != nil {
		return authorizationapp.ContextProjectionEvidence{}, analysis.ErrUnavailable
	}
	return out, nil
}
