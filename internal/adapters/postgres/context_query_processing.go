package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/authorization"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextProjectionProcessing consumes the independent approved-source record.
// The historically named DownloadProcessingProof is neutral processing state;
// no download evidence, environment, policy or authority is constructed here.
func (s *ProcessingReads) ContextProjectionProcessing(ctx context.Context, r app.ContextProjectionEvidence, recovery artifact.RecoveryProof) (artifact.DownloadProcessingProof, error) {
	var out artifact.DownloadProcessingProof
	now := time.Now()
	if s == nil || s.ledger == nil || s.recovery == nil || ctx == nil || ctx.Err() != nil || !identity.Fresh(r.ObservedAt, r.ValidUntil, now, identity.EvidenceReadRequestWindow) || !recovery.Valid(now) || r.CaseID == "" || r.SourceFormat != artifact.ContextFormat || r.SourceProjectionDigest != value.ContextSourceProjectionDigest() || r.DataClass != "metadata" || r.Retained.Registration.NativeLimit != artifact.MaxContextBytes {
		return out, value.ErrUnavailable
	}
	until := identity.Earlier(r.ValidUntil, identity.Earlier(recovery.FreshUntil, r.Retained.Effective.ExpiresAt))
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	e := s.ledger.transaction(ctx, func(tx *custodydb.Queries) error {
		trust, e := s.recovery.lock(ctx, tx, s.root, recovery)
		if e != nil {
			return e
		}
		started, e := tx.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !identity.Fresh(r.ObservedAt, r.ValidUntil, started.Time, identity.EvidenceReadRequestWindow) || !recovery.Valid(started.Time) || ctx.Err() != nil {
			return value.ErrUnavailable
		}
		snapshot, p, e := readProcessingSnapshot(ctx, tx, s.root, s.recovery.installation, recovery.IssuerEpoch, r.Retained.Registration.Location.ArtifactID, r.ObservedAt, until)
		if e != nil {
			return e
		}
		node := snapshot.Nodes[0]
		if node.CaptureID != r.CaptureID || node.Location != r.Retained.Registration.Location || node.Target != r.Retained.Input.Target || !node.AnchorAt.Equal(r.Retained.Registration.AnchorAt) || !node.DeleteBy.Equal(r.Retained.Registration.DeleteBy) {
			return value.ErrUnavailable
		}
		published, e := tx.ReadPublishedContext(ctx, custodydb.ReadPublishedContextParams{ArtifactID: id(node.Location.ArtifactID), RootID: id(s.root)})
		if e != nil {
			return e
		}
		original, e := currentPublishedContext(published)
		if e != nil || original.CaseID != r.CaseID || original.CaptureUID != r.CaptureID || original.Registration != r.Retained.Registration || original.PurposeRef != r.PurposeRef || original.DataClass != r.DataClass || artifact.Digest(published.ContextVerification.CopiesDigest) != r.Version {
			return value.ErrUnavailable
		}
		out = processingProof(snapshot, p)
		if e = s.recovery.check(ctx, tx, trust, s.root, recovery); e != nil {
			return e
		}
		end, e := tx.CurrentTime(ctx)
		if e != nil || ctx.Err() != nil || !end.Time.Before(until) || !out.Valid(end.Time) {
			return value.ErrUnavailable
		}
		return nil
	})
	if e != nil || ctx.Err() != nil {
		return artifact.DownloadProcessingProof{}, value.ErrUnavailable
	}
	return out, nil
}
