package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"crypto/hmac"
	"crypto/sha256"
)

// LiveDigest reuses the existing installation account key with a separate
// purpose. It authenticates opaque viewer cursors/control keys, not content;
// audit input-key rotation cannot reset budgets or make another owner current.
func (m *OperationMAC) LiveDigest(domain string, canonical []byte) (artifact.Digest, error) {
	if m == nil || len(canonical) == 0 || len(canonical) > 16<<10 || (domain != "cursor" && domain != "principal" && domain != "workload" && domain != "open-key" && domain != "selection" && domain != "source-handle") {
		return artifact.Digest{}, ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.accountKey) != 32 {
		return artifact.Digest{}, ErrUnavailable
	}
	h := hmac.New(sha256.New, m.accountKey)
	_, _ = h.Write([]byte("asservat-live-watch/" + domain + "/v1\x00"))
	_, _ = h.Write(canonical)
	var out artifact.Digest
	copy(out[:], h.Sum(nil))
	return out, nil
}
