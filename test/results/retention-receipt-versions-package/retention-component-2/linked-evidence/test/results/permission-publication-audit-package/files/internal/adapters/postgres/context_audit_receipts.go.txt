package postgres

import (
	"bytes"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

// Current effects consume the complete retained acknowledgement of the exact
// selected protocol. Neither a state flag nor a later source observation repairs
// an unversioned historical receipt. This performs no additional database read.
func acceptedPublication(row custodydb.ContextCapture) (artifact.ContextExpectation, error) {
	e, err := historicalPublication(row)
	if err != nil {
		return artifact.ContextExpectation{}, err
	}
	if row.IntentOperationID.Valid {
		snapshot, err := exactCaptureOperationIntent(row)
		if err != nil || snapshot.Receipt == nil {
			return artifact.ContextExpectation{}, privacy.ErrFence
		}
	} else {
		snapshot, err := exactCaptureIntent(row)
		if err != nil || snapshot.Receipt == nil {
			return artifact.ContextExpectation{}, privacy.ErrFence
		}
	}
	return e, nil
}

func currentVerificationReceipt(v custodydb.ContextVerification) bool {
	if !v.AuditAcknowledgedAt.Valid || !v.VerifiedAt.Valid || v.AuditAcknowledgedAt.Time.Before(v.VerifiedAt.Time) || !v.AuditObjectKey.Valid || !v.AuditObjectVersion.Valid || !v.AuditObjectEtag.Valid || !v.AuditObjectBytes.Valid || len(v.AuditObjectSha256) != 32 || len(v.AuditDigest) != 32 || bytes.Equal(v.AuditDigest, make([]byte, 32)) {
		return false
	}
	r := audit.Receipt{Key: v.AuditObjectKey.String, Version: v.AuditObjectVersion.String, ETag: v.AuditObjectEtag.String, Bytes: v.AuditObjectBytes.Int64}
	copy(r.SHA256[:], v.AuditObjectSha256)
	return r.ValidContextVerification(uid(v.RootID), uid(v.CaptureID))
}

// The query already joins both immutable records. Validate that same snapshot
// at every current catalog/key/disclosure consumer, retaining its original
// effective dates. API execution provenance remains the execution gate's job.
func currentPublishedContext(row custodydb.ReadPublishedContextRow) (artifact.ContextExpectation, error) {
	c, v := row.ContextCapture, row.ContextVerification
	e, err := acceptedPublication(c)
	if err != nil {
		return artifact.ContextExpectation{}, err
	}
	if !currentVerificationReceipt(v) || v.RootID != c.RootID || v.CaptureID != c.ID || !bytes.Equal(v.ExpectationDigest, digest(e)) || !bytes.Equal(v.IntentDigest, c.IntentDigest) || len(v.CopiesDigest) != 32 || bytes.Equal(v.CopiesDigest, make([]byte, 32)) || !row.PublishedAt.Valid || row.PublishedAt.Time.Before(v.AuditAcknowledgedAt.Time) || !row.PublishedAt.Time.Before(e.Registration.WriteUntil) {
		return artifact.ContextExpectation{}, privacy.ErrFence
	}
	return e, nil
}
