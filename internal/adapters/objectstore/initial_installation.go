package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	port "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"errors"
	"time"
)

// Bootstrap-only key/store credentials are supplied by protected installation,
// not an ordinary evidence authority that would depend on already-active SQL.
type InitialInstallationObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

var _ port.InitialInstallationWriter = (*InitialInstallationObjects)(nil)

func (a *InitialInstallationObjects) WriteInitialInstallation(ctx context.Context, r audit.InitialInstallation) (audit.Receipt, error) {
	var zero audit.Receipt
	if a == nil || a.Store == nil || a.Seal == nil || a.Open == nil || !r.Valid() {
		return zero, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	key := audit.InitialInstallationKey(r.Scope.InstallationID, r.Claim.ID)
	cipher, err := framed.SealInitialInstallation(ctx, a.Seal, r)
	if err != nil {
		return zero, err
	}
	put, err := a.Store.PutSmall(ctx, key, cipher)
	if err != nil && !errors.Is(err, ErrExists) {
		return zero, err
	}
	var object Object
	var body []byte
	if err == nil {
		// A successful PUT already identifies the exact version. A mutable latest
		// pointer cannot substitute a different receipt before acknowledgement.
		object, body, err = a.Store.readAcknowledgedControlAudit(ctx, put, 128<<10)
	} else {
		// Existing-object reconciliation retains the original protocol: no
		// repeated PUT or inferred completion, and full record verification below.
		object, body, err = a.Store.readControlAudit(ctx, key, 128<<10)
	}
	if err != nil {
		return zero, err
	}
	if err = framed.VerifyInitialInstallation(ctx, a.Open, r, body); err != nil {
		return zero, err
	}
	out := audit.Receipt{Key: key, Version: object.VersionID, ETag: object.ETag, Bytes: object.Bytes, SHA256: object.SHA256}
	if !out.ValidInitialInstallation(r.Scope.InstallationID, r.Claim.ID) {
		return zero, artifact.ErrIntegrity
	}
	return out, nil
}
