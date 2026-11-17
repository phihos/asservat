package postgres

import (
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgtype"
)

// catalogAcquisition reads the profile acquisition window stored with the
// catalog row. SQL dispatch or completion times never replace absent metadata.
func catalogAcquisition(e artifact.ContextExpectation, started, completed pgtype.Timestamptz) (*artifact.AcquisitionWindow, error) {
	if started.Valid != completed.Valid {
		return nil, artifact.ErrIntegrity
	}
	if !started.Valid {
		return nil, nil
	}
	if started.InfinityModifier != 0 || completed.InfinityModifier != 0 {
		return nil, artifact.ErrIntegrity
	}
	w := &artifact.AcquisitionWindow{StartedAt: started.Time.UTC(), CompletedAt: completed.Time.UTC()}
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

// catalogFacts returns the native size and profile acquisition window that
// publication stored, for the reader to compare with the authenticated
// manifest. A row without a native size predates one-step publication and is
// refused.
func catalogFacts(e artifact.ContextExpectation, cat custodydb.ContextCatalog) (artifact.CatalogFacts, error) {
	w, err := catalogAcquisition(e, cat.AcquisitionStartedAt, cat.AcquisitionCompletedAt)
	if err != nil || !cat.NativeBytes.Valid || (e.Profile != nil) != (w != nil) {
		return artifact.CatalogFacts{}, artifact.ErrIntegrity
	}
	return artifact.CatalogFacts{NativeBytes: cat.NativeBytes.Int64, Acquisition: w}, nil
}
