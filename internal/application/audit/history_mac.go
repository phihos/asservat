package audit

import (
	"crypto/hmac"
	"crypto/sha256"

	"asservat.local/asservat/internal/domain/artifact"
)

// HistoryDigest uses the installation's existing stable account key, loaded
// through newPublicOperationMAC's protected root/setup projection. Ordinary
// audit input-key rotation cannot regroup selectors or reset settings identity.
func (m *OperationMAC) HistoryDigest(domain string, canonical []byte) (artifact.Digest, error) {
	if m == nil || (domain != "selector" && domain != "settings" && domain != "cursor") || len(canonical) == 0 || len(canonical) > (128<<10)+512 {
		return artifact.Digest{}, ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.accountKey) != 32 {
		return artifact.Digest{}, ErrUnavailable
	}
	h := hmac.New(sha256.New, m.accountKey)
	_, _ = h.Write([]byte("asservat-capture-history/" + domain + "/v1\x00"))
	_, _ = h.Write(canonical)
	var out artifact.Digest
	copy(out[:], h.Sum(nil))
	return out, nil
}
