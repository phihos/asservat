package postgres

import (
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
)

// currentAuditedWorker is for current identity/effects only. decodeWorker stays
// structural so original termination and physical retirement remain possible.
func currentAuditedWorker(row custodydb.DownloadWorker) (value.DownloadWorker, error) {
	w, err := decodeWorker(row)
	var receipt audit.Receipt
	if err != nil || !row.ClaimedAt.Valid || row.TerminationJson != nil || row.RetiredProofJson != nil || json.Unmarshal(row.AuditReceiptJson, &receipt) != nil || !receipt.ValidDownloadWorker(w.Intent) {
		return value.DownloadWorker{}, artifact.ErrDownloadUnavailable
	}
	return w, nil
}

func currentAuditedWorkerEnrollment(ctx context.Context, q *custodydb.Queries, w value.DownloadWorker) (value.WorkerEnrollment, error) {
	row, err := q.ReadWorkerEnrollment(ctx, id(w.Intent.ID))
	if err != nil {
		return value.WorkerEnrollment{}, err
	}
	enrollment, err := decodeWorkerEnrollment(row, w)
	if err != nil {
		return value.WorkerEnrollment{}, err
	}
	if _, acknowledged, err := enrollmentReceipt(row, enrollment); err != nil || !acknowledged {
		return value.WorkerEnrollment{}, artifact.ErrDownloadUnavailable
	}
	return enrollment, nil
}
