package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"sync"

	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// OperationMAC keeps stable account identity separate from rotatable input/output
// MACs. Both keys have distinct protected purposes, neither is a wrapping root or
// login secret. Account-key migration requires a verified mapping retaining spend;
// ordinary audit-key rotation never creates a new account.
type OperationMAC struct {
	mu                      sync.Mutex
	key, accountKey         []byte
	version, accountVersion string
}

func NewOperationMAC(version string, key []byte, accountVersion string, accountKey []byte) (*OperationMAC, error) {
	if !identity.Text(version, 64) || !identity.Text(accountVersion, 64) || len(key) != 32 || len(accountKey) != 32 || subtle.ConstantTimeCompare(key, accountKey) == 1 {
		return nil, ErrUnavailable
	}
	return &OperationMAC{key: append([]byte(nil), key...), accountKey: append([]byte(nil), accountKey...), version: version, accountVersion: accountVersion}, nil
}
func (m *OperationMAC) Close() {
	if m != nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		clear(m.key)
		clear(m.accountKey)
		m.key = nil
		m.accountKey = nil
	}
}
func (m *OperationMAC) Version() string {
	if m == nil {
		return ""
	}
	return m.version
}
func (m *OperationMAC) AccountVersion() string {
	if m == nil {
		return ""
	}
	return m.accountVersion
}
func (m *OperationMAC) Digest(domain string, b []byte) (artifact.Digest, error) {
	return m.digest(domain, b, 64<<10)
}

// BrowserSettingsResultDigest hashes only the already prepared canonical
// response. It uses the existing result domain/key and stores no plaintext.
// Callers still enforce the authenticated browser/name-specific response bound.
func (m *OperationMAC) BrowserSettingsResultDigest(b []byte) (artifact.Digest, error) {
	return m.digest("mcp-result/v1", b, auditvalue.OperationCaptureSettingsOutputLimit)
}

// ResultBoundDigest hashes a result up to the MCP result bound.
func (m *OperationMAC) ResultBoundDigest(b []byte) (artifact.Digest, error) {
	return m.digest("mcp-result/v1", b, auditvalue.OperationResultBound)
}

func (m *OperationMAC) digest(domain string, b []byte, limit int) (artifact.Digest, error) {
	if m == nil || len(b) > limit || (domain != "context-query-input/v1" && domain != "native-content-input/v1" && domain != "native-content-result/v1" && domain != "context-input/v1" && domain != "invalid-input/v1" && domain != "mcp-result/v1" && domain != "operation-error/v1" && domain != "principal/v1" && domain != "processing-input/v1" && domain != "processing-result/v1" && domain != "capture-intent/v2" && domain != "capture-intent-reason/v1" && domain != "capture-intent-result/v1") {
		return artifact.Digest{}, ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.key) != 32 {
		return artifact.Digest{}, ErrUnavailable
	}
	key := m.key
	if domain == "principal/v1" {
		key = m.accountKey
	}
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("asservat-operation-audit/" + domain + "\x00"))
	_, _ = h.Write(b)
	var d artifact.Digest
	copy(d[:], h.Sum(nil))
	return d, nil
}
func (m *OperationMAC) Principal(p identity.Principal) (artifact.Digest, error) {
	if !p.Valid() {
		return artifact.Digest{}, ErrUnavailable
	}
	// Deliberately omit client: another approved client does not reset capacity.
	b, e := json.Marshal(struct {
		Issuer, Subject string
		Kind            identity.Kind
	}{p.Issuer, p.Subject, p.Kind})
	if e != nil {
		return artifact.Digest{}, ErrUnavailable
	}
	defer clear(b)
	return m.Digest("principal/v1", b)
}

// CaptureAccount retains the exact workload allocation's capacity across human,
// client and input-MAC rotations. Account-key migration cannot reset spend.
func (m *OperationMAC) CaptureAccount(installation, root, allocation string) (artifact.Digest, error) {
	if m == nil || !authorization.UUID(installation) || !authorization.UUID(root) || !authorization.UUID(allocation) {
		return artifact.Digest{}, ErrUnavailable
	}
	b, e := json.Marshal(struct{ Installation, Root, Allocation string }{installation, root, allocation})
	if e != nil {
		return artifact.Digest{}, ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.accountKey) != 32 {
		return artifact.Digest{}, ErrUnavailable
	}
	h := hmac.New(sha256.New, m.accountKey)
	_, _ = h.Write([]byte("asservat-operation-audit/capture-account/v1\x00"))
	_, _ = h.Write(b)
	var d artifact.Digest
	copy(d[:], h.Sum(nil))
	return d, nil
}
