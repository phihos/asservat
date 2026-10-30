package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
)

// NewCaptureReasonCipher reuses the hub audit/control key ports. Callers must
// authorize display before invoking OpenCaptureReason; this codec grants none.
func NewCaptureReasonCipher(sealer evidence.KeySealer, opener evidence.KeyOpener) (audit.CaptureReasonCipher, error) {
	if sealer == nil || opener == nil {
		return nil, audit.ErrUnavailable
	}
	return framed.CaptureReasonCipher{Sealer: sealer, Opener: opener}, nil
}
