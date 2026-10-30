package capture

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
	"time"
)

func TestReasonDisplayExpiryDoesNotCloseCaptureReview(t *testing.T) {
	p := domainPreview()
	if !p.Valid() {
		t.Fatal("valid baseline required")
	}
	p.Intent.Reason = &ProtectedReasonRef{ID: p.ID, CiphertextDigest: artifact.Digest{9}, ExpiresAt: p.CreatedAt.Add(-time.Second)}
	if !p.Valid() || !p.Current(p.CreatedAt) {
		t.Fatal("descriptive reason expiry changed capture review authority")
	}
	p.Intent.Reason.ExpiresAt = time.Time{}
	if !p.Valid() {
		t.Fatal("audit-governed reference needs no independent TTL")
	}
}
