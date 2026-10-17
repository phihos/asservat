package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"sync"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// CaptureAccounts is the capacity compartment's purpose-specific account port.
// It has no input/output MAC key, human-principal account method or mutable
// version. Its installation pin is independent of the allocation argument.
type CaptureAccounts struct {
	mu                    sync.Mutex
	installation, version string
	key                   []byte
}

func NewCaptureAccounts(installation, version string, key []byte) (*CaptureAccounts, error) {
	if !authorization.UUID(installation) || !identity.Text(version, 64) || len(key) != 32 {
		return nil, ErrUnavailable
	}
	return &CaptureAccounts{installation: installation, version: version, key: append([]byte(nil), key...)}, nil
}
func (m *CaptureAccounts) AccountVersion() string {
	if m == nil {
		return ""
	}
	return m.version
}
func (m *CaptureAccounts) CaptureAccount(root, allocation string) (artifact.Digest, error) {
	if m == nil || !authorization.UUID(root) || !authorization.UUID(allocation) {
		return artifact.Digest{}, ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.key) != 32 {
		return artifact.Digest{}, ErrUnavailable
	}
	// Exact existing OperationMAC.CaptureAccount layout; key version changes
	// cannot silently replace the stable account key under this constructor.
	b, e := json.Marshal(struct{ Installation, Root, Allocation string }{m.installation, root, allocation})
	if e != nil {
		return artifact.Digest{}, ErrUnavailable
	}
	h := hmac.New(sha256.New, m.key)
	_, _ = h.Write([]byte("asservat-operation-audit/capture-account/v1\x00"))
	_, _ = h.Write(b)
	var out artifact.Digest
	copy(out[:], h.Sum(nil))
	return out, nil
}
func (m *CaptureAccounts) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.key)
	m.key = nil
}
