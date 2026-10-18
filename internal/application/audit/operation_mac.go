package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"sync"
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
	if m == nil || len(b) > 64<<10 || (domain != "context-query-input/v1" && domain != "native-content-input/v1" && domain != "native-content-result/v1" && domain != "context-input/v1" && domain != "invalid-input/v1" && domain != "mcp-result/v1" && domain != "operation-error/v1" && domain != "principal/v1" && domain != "processing-input/v1" && domain != "processing-result/v1" && domain != "capture-intent/v2" && domain != "capture-intent-result/v1" && domain != "connector-retirement/v1" && domain != "connector-backing/v1" && domain != "connector-process/v1" && domain != "connector-credential/v1" && domain != "connector-result/v1") {
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

// ConnectorAccount keeps one charged account across leaf, process and issuer
// rotation. It does not admit a peer or a signing operation. The new purpose has
// its own domain separator; a human account can never collide by choosing names.
func (m *OperationMAC) ConnectorAccount(p fleet.PeerBinding) (artifact.Digest, error) {
	if m == nil || !p.Valid() || p.Role != fleet.ConnectorPeer {
		return artifact.Digest{}, ErrUnavailable
	}
	b, e := json.Marshal(struct {
		InstallationID, ClusterID, PeerID string
		Role                              fleet.PeerRole
	}{p.InstallationID, p.ClusterID, p.PeerID, p.Role})
	if e != nil {
		return artifact.Digest{}, ErrUnavailable
	}
	defer clear(b)
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.accountKey) != 32 {
		return artifact.Digest{}, ErrUnavailable
	}
	h := hmac.New(sha256.New, m.accountKey)
	_, _ = h.Write([]byte("asservat-operation-audit/connector-account/v1\x00"))
	_, _ = h.Write(b)
	var d artifact.Digest
	copy(d[:], h.Sum(nil))
	return d, nil
}

// ProcessingAccount reserves capacity for a fixed rule, independently of which
// currently authorized human performs release. Actor remains the actual human
// in every record. Input MAC rotation and rule toggles never mint new capacity.
func (m *OperationMAC) ProcessingAccount(installation, root, rule string) (artifact.Digest, error) {
	if m == nil || !authorization.UUID(installation) || !authorization.UUID(root) || !authorization.UUID(rule) {
		return artifact.Digest{}, ErrUnavailable
	}
	b, e := json.Marshal(struct{ Installation, Root, Rule string }{installation, root, rule})
	if e != nil {
		return artifact.Digest{}, ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.accountKey) != 32 {
		return artifact.Digest{}, ErrUnavailable
	}
	h := hmac.New(sha256.New, m.accountKey)
	_, _ = h.Write([]byte("asservat-operation-audit/processing-account/v1\x00"))
	_, _ = h.Write(b)
	var d artifact.Digest
	copy(d[:], h.Sum(nil))
	return d, nil
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
