package capture

import (
	"crypto/sha256"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
)

// ValidContextPreview adds serialized bounds and integrity to domain structural
// validation. It does not restore current authority from a persisted preview.
func ValidContextPreview(p value.ContextPreview) bool {
	if !p.Valid() || !validPreviewReason(p) || !json.Valid(p.CanonicalScope) || artifact.Digest(sha256.Sum256(p.CanonicalScope)) != p.ScopeDigest {
		return false
	}
	b, err := json.Marshal(p)
	return err == nil && len(b) <= value.MaxContextPreviewBytes
}

// ContextRequestDigest is derivable without loading an expired preview. Actor,
// client and key are independently bound by the admission transaction.
func ContextRequestDigest(previewID string) artifact.Digest {
	if !authorization.UUID(previewID) {
		return artifact.Digest{}
	}
	return artifact.Digest(sha256.Sum256([]byte("asservat-context-preview-request/v1\x00" + previewID)))
}

func ValidReplayQuery(q value.ReplayQuery, now time.Time) bool {
	return q.Valid(now) && q.SubmissionDigest == ContextRequestDigest(q.PreviewID)
}
