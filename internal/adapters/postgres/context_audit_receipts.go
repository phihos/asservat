package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
)

// acceptedPublication validates the accepted capture row's durable structure.
func acceptedPublication(row custodydb.ContextCapture) (artifact.ContextExpectation, error) {
	e, err := historicalPublication(row)
	if err != nil {
		return artifact.ContextExpectation{}, err
	}
	return e, nil
}

// currentPublishedContext validates the joined capture and catalog row at
// every current catalog, key and disclosure consumer.
func currentPublishedContext(row custodydb.ReadPublishedContextRow) (artifact.ContextExpectation, error) {
	c, cat := row.ContextCapture, row.ContextCatalog
	e, err := acceptedPublication(c)
	if err != nil {
		return artifact.ContextExpectation{}, err
	}
	if _, err := catalogAcquisition(e, cat.AcquisitionStartedAt, cat.AcquisitionCompletedAt); err != nil {
		return artifact.ContextExpectation{}, privacy.ErrFence
	}
	if cat.NativeBytes.Valid && (cat.NativeBytes.Int64 < 0 || cat.NativeBytes.Int64 > e.Registration.NativeLimit) || cat.RootID != c.RootID || cat.CaptureID != c.ID || len(cat.CopiesDigest) != 32 || !cat.PublishedAt.Valid || !cat.PublishedAt.Time.Before(e.Registration.WriteUntil) {
		return artifact.ContextExpectation{}, privacy.ErrFence
	}
	return e, nil
}
