package objectstore

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"time"
)

// ContextNativeReader runs only in the independently authorized regional
// download/acquisition role. It does not create a session or grant access.
type ContextNativeReader struct{ verifier *ContextVerifier }

var _ evidence.ContextNativeReader = (*ContextNativeReader)(nil)

func NewContextNativeReader(store *CustodyStore, keys evidence.KeyOpener) (*ContextNativeReader, error) {
	v, err := NewContextVerifier(store, keys)
	if err != nil {
		return nil, err
	}
	return &ContextNativeReader{v}, nil
}
func (r *ContextNativeReader) ReadContext(ctx context.Context, e artifact.ContextExpectation, c artifact.Copies, leaseUntil time.Time) ([]byte, error) {
	now := time.Now()
	if r == nil || r.verifier == nil || e.DataClass != "metadata" || !now.Before(leaseUntil) || leaseUntil.After(now.Add(5*time.Second)) {
		return nil, artifact.ErrInvalid
	}
	// Downloads remain possible after acquisition's write window closes, but
	// neither a caller lease nor a successful decrypt can extend read retention.
	return r.verifier.readContext(ctx, e, c, minDeadline(leaseUntil, e.Registration.ExpiresAt))
}
