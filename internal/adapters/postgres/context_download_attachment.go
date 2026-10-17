package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

var _ evidence.ContextDownloadAttachments = (*DownloadWorkers)(nil)

// The existing current recovery/permission/session/configuration locks enclose
// SELECT-only business reads. No historical row is a refreshed worker proof.
func (s *DownloadWorkers) ReadContextDownloadAttachment(ctx context.Context, sessionID string, a artifact.DownloadAuthority) (evidence.ContextDownloadAttachment, error) {
	var out evidence.ContextDownloadAttachment
	if s == nil || ctx == nil || ctx.Err() != nil || !value.UUID(sessionID) || !a.Valid(time.Now()) {
		return out, artifact.ErrDownloadUnavailable
	}
	call, end := context.WithDeadline(ctx, a.ValidUntil)
	defer end()
	err := s.withSession(call, sessionID, a, func(q *custodydb.Queries, session artifact.DownloadSession, now time.Time) error {
		out = evidence.ContextDownloadAttachment{SessionID: session.ID, Scope: session.Scope, State: session.State, ObservedAt: now, ValidUntil: downloadObservationDeadline(call, now, a.ValidUntil, session.Deadline)}
		workers, err := q.ReadContextDownloadWorkers(call, custodydb.ReadContextDownloadWorkersParams{SessionID: id(session.ID), RootID: id(s.downloads.root)})
		if err != nil || len(workers) > 1 {
			return artifact.ErrDownloadUnavailable
		}
		batches, err := q.ReadFirstContextDownloadBatches(call, id(session.ID))
		if err != nil || len(batches) > 1 {
			return artifact.ErrDownloadUnavailable
		}
		if len(workers) == 0 {
			if len(batches) != 0 {
				return artifact.ErrDownloadUnavailable
			}
			return nil
		}
		row := workers[0]
		out.Intent, err = decodeWorkerIntent(row)
		if err != nil || out.Intent.Generation != 1 || out.Intent.Profile != s.profile || out.Intent.Authority.Scope != session.Scope || row.TerminationJson != nil || row.RetiredProofJson != nil {
			return artifact.ErrDownloadUnavailable
		}
		control, err := readContextNativeControl(call, q, session, out.Intent.ID)
		if err != nil {
			return err
		}
		out.NativeBusy, out.ResponseBusy, out.NativeUncertain = control.nativeBusy, control.responseBusy, control.uncertain
		out.NativeTransitions = control.remaining
		out.Found = true
		out.ValidUntil = identity.Earlier(out.ValidUntil, out.Intent.RunUntil)
		if row.BindingJson != nil {
			w, err := decodeWorker(row)
			var receipt audit.Receipt
			if err != nil || json.Unmarshal(row.AuditReceiptJson, &receipt) != nil || !receipt.ValidDownloadWorker(w.Intent) {
				return artifact.ErrDownloadUnavailable
			}
			out.Worker = &w
			enrolled, err := q.ReadWorkerEnrollment(call, row.ID)
			if err == nil {
				en, e := decodeWorkerEnrollment(enrolled, w)
				if e != nil {
					return e
				}
				_, ack, e := enrollmentReceipt(enrolled, en)
				if e != nil {
					return e
				}
				if ack {
					out.Enrollment = &en
					epoch, _, e := value.WorkerCertificateEpoch(w, now)
					if e != nil {
						return e
					}
					certificates, e := q.ReadContextWorkerCertificates(call, custodydb.ReadContextWorkerCertificatesParams{WorkerID: row.ID, CurrentEpoch: int32(epoch), PreviousEpoch: int32(epoch - 1)})
					if e != nil || len(certificates) > 4 {
						return artifact.ErrDownloadUnavailable
					}
					for _, candidate := range certificates {
						attempt, e := decodeWorkerCertificateAttempt(candidate)
						if e != nil || attempt.Enrollment != en || attempt.RecoveryEpoch != a.Environment.RecoveryEpoch {
							return artifact.ErrDownloadUnavailable
						}
						cert, e := decodeWorkerCertificate(candidate, attempt)
						var signedReceipt audit.Receipt
						if e != nil || json.Unmarshal(candidate.AuditReceiptJson, &signedReceipt) != nil || !signedReceipt.ValidWorkerCertificate(audit.WorkerCertificate{Attempt: attempt, Peer: cert.Peer}) {
							return artifact.ErrDownloadUnavailable
						}
						if out.ActivatedPeer == nil && cert.Peer.Valid(now) {
							peer := cert.Peer
							out.ActivatedPeer = &peer
						}
					}
				}
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		out.MetadataAttempted = len(batches) != 0
		if out.MetadataAttempted {
			b := batches[0]
			intent, err := decodeDownloadIntent(b)
			if err != nil || intent.SessionID != session.ID || intent.Batch.Authority.Scope != session.Scope || intent.Batch.Purpose != artifact.DownloadMetadata {
				return artifact.ErrDownloadUnavailable
			}
			// Partial/unknown preparation remains visible only as spent. It never
			// supplies a new batch ID or permits another metadata/key preparation.
			if b.OutcomeAcknowledgedAt.Valid {
				if out.Enrollment == nil {
					return artifact.ErrDownloadUnavailable
				}
				key, err := q.ReadDownloadKeyBinding(call, custodydb.ReadDownloadKeyBindingParams{BatchID: b.ID, RootID: id(s.downloads.root)})
				if err != nil {
					return err
				}
				prepared, err := acknowledgedContextPreparation(b, key, *out.Enrollment, session.Scope)
				if err != nil {
					return err
				}
				out.Preparation = &prepared
			}
		}
		return nil
	})
	if err != nil || call.Err() != nil || !out.Valid(time.Now()) {
		return evidence.ContextDownloadAttachment{}, artifact.ErrDownloadUnavailable
	}
	return out, nil
}

func acknowledgedContextPreparation(b custodydb.DownloadBatch, k custodydb.DownloadKeyBinding, en value.WorkerEnrollment, scope artifact.DownloadScope) (artifact.DownloadPreparation, error) {
	var zero artifact.DownloadPreparation
	in, err := decodeDownloadIntent(b)
	var outcome audit.DownloadOutcome
	var intentReceipt, outcomeReceipt audit.Receipt
	var proof value.KeyWorkerProof
	var authority artifact.DownloadAuthority
	if err != nil || !en.Valid() || in.SessionID != en.Worker.Intent.SessionID || in.Batch.Authority.Scope != scope || in.Batch.Purpose != artifact.DownloadMetadata || !b.AuditAcknowledgedAt.Valid || !b.OutcomeAcknowledgedAt.Valid || json.Unmarshal(b.AuditReceiptJson, &intentReceipt) != nil || !intentReceipt.ValidDownload(scope.RootID, in.SessionID, in.Batch.ID, "intent") || json.Unmarshal(b.OutcomeJson, &outcome) != nil || !outcome.Valid() || !outcome.Intent.Equal(in) || !outcome.Success || outcome.EmittedBytes != 0 || outcome.FullFile || json.Unmarshal(b.OutcomeReceiptJson, &outcomeReceipt) != nil || !outcomeReceipt.ValidDownload(scope.RootID, in.SessionID, in.Batch.ID, "outcome") {
		return zero, artifact.ErrDownloadUnavailable
	}
	// Validate the old proof at the original key-binding admission, as immutable
	// provenance of the acknowledged read. NativeObserve must obtain a separate
	// live peer/Pod/source proof; no old timestamp is modified or used as authority.
	if json.Unmarshal(k.WorkerProofJson, &proof) != nil || !k.CreatedAt.Valid || !proof.Valid(k.CreatedAt.Time) || proof.Binding != en.Worker.Binding || proof.Peer.Role != "acquisition" || k.BatchID != b.ID || uid(k.SessionID) != in.SessionID || uid(k.RootID) != scope.RootID || uid(k.InstallationID) != en.Worker.Binding.InstallationID || uid(k.PeerID) != en.Worker.Binding.PodUID || !bytes.Equal(k.CertificateSha256, proof.Peer.Certificate[:]) || k.UsedRoles != 7 || !k.ValidUntil.Valid || k.ValidUntil.Time.After(proof.FreshUntil) || json.Unmarshal(k.AuthorityJson, &authority) != nil || !authority.Valid(k.CreatedAt.Time) || k.CreatedAt.Time.Before(in.Batch.StartedAt) || k.ValidUntil.Time.After(authority.ValidUntil) || k.ValidUntil.Time.After(in.Batch.LeaseUntil) || authority.Scope != scope {
		return zero, artifact.ErrDownloadUnavailable
	}
	out := artifact.DownloadPreparation{SessionID: in.SessionID, BatchID: in.Batch.ID, Generation: in.Batch.Generation}
	if !out.Valid() {
		return zero, artifact.ErrDownloadUnavailable
	}
	return out, nil
}
