package postgres

import (
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
)

// verifiedAcquisition consumes only the already joined immutable verification
// row. SQL dispatch or completion times never replace absent metadata.
func verifiedAcquisition(e artifact.ContextExpectation, v custodydb.ContextVerification) (*artifact.AcquisitionWindow, error) {
	if v.AcquisitionStartedAt.Valid != v.AcquisitionCompletedAt.Valid {
		return nil, artifact.ErrIntegrity
	}
	if !v.AcquisitionStartedAt.Valid {
		return nil, nil
	}
	if v.AcquisitionStartedAt.InfinityModifier != 0 || v.AcquisitionCompletedAt.InfinityModifier != 0 {
		return nil, artifact.ErrIntegrity
	}
	w := &artifact.AcquisitionWindow{StartedAt: v.AcquisitionStartedAt.Time.UTC(), CompletedAt: v.AcquisitionCompletedAt.Time.UTC()}
	if !acquisitionMatchesExpectation(e, w) {
		return nil, artifact.ErrIntegrity
	}
	return w, nil
}

func acquisitionMatchesExpectation(e artifact.ContextExpectation, w *artifact.AcquisitionWindow) bool {
	return w != nil && e.Profile != nil && w.Valid() && w.StartedAt.Nanosecond()%1000 == 0 && w.CompletedAt.Nanosecond()%1000 == 0 &&
		!w.StartedAt.Before(e.Registration.AnchorAt.Truncate(time.Microsecond)) &&
		!w.StartedAt.Before(e.TriggeredAt.Truncate(time.Microsecond)) && w.CompletedAt.Before(e.Registration.WriteUntil)
}

func sameAcquisition(a, b *artifact.AcquisitionWindow) bool {
	return a != nil && b != nil && a.StartedAt.Equal(b.StartedAt) && a.CompletedAt.Equal(b.CompletedAt)
}
