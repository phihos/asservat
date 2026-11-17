package authorization

import (
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type KeyScope struct{ InstallationID, Purpose, KeyID string }

func (s KeyScope) Valid() bool {
	if !UUID(s.InstallationID) || len(s.KeyID) < 1 || len(s.KeyID) > 128 {
		return false
	}
	for _, c := range s.KeyID {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return s.Purpose == "artifact" || s.Purpose == "audit" || s.Purpose == "browser-credentials"
}

// KeyPeer comes from a current verified TLS certificate, never request JSON or
// proxy headers. The certificate identifies a process; it is not an operation
// grant. Current accepted authority must separately bind each request.
type KeyPeer struct {
	InstallationID, PeerID, Role string
	// ClusterID is a connector's token-attributed cluster; empty otherwise.
	ClusterID           string
	Certificate         artifact.Digest
	NotBefore, NotAfter time.Time
}

func (p KeyPeer) Valid(now time.Time) bool {
	if !UUID(p.InstallationID) || !UUID(p.PeerID) || p.Certificate == (artifact.Digest{}) || p.NotBefore.IsZero() || now.Before(p.NotBefore) || !now.Before(p.NotAfter) || p.NotAfter.Sub(p.NotBefore) > time.Hour {
		return false
	}
	switch p.Role {
	case "collector", "acquisition", "audit-writer", "audit-reader", "hub-session", "policy-submitter":
		return true
	}
	return false
}

// CanRequest is only a fixed negative guard. A matching role/purpose does not
// authorize the operation, its binding, key version or authority reference.
func (p KeyPeer) CanRequest(scope KeyScope, operation string) bool {
	if p.InstallationID != scope.InstallationID {
		return false
	}
	switch scope.Purpose {
	case "artifact":
		return operation == "wrap" && p.Role == "collector" || operation == "unwrap" && p.Role == "acquisition"
	case "audit":
		return operation == "wrap" && p.Role == "audit-writer" || operation == "unwrap" && p.Role == "audit-reader"
	case "browser-credentials":
		return (operation == "wrap" || operation == "unwrap") && p.Role == "hub-session"
	}
	return false
}

type KeyRequest struct {
	Scope       KeyScope
	AuthorityID string
	Operation   string
	Binding     []byte
	Input       []byte
	Sealed      artifact.SealedKey
}

func (r KeyRequest) Valid() bool {
	if !r.Scope.Valid() || !UUID(r.AuthorityID) {
		return false
	}
	if len(r.Binding) < 1 || len(r.Binding) > 2048 {
		return false
	}
	if r.Operation == "wrap" {
		return len(r.Input) >= 1 && len(r.Input) <= 4096 && r.Sealed == (artifact.SealedKey{})
	}
	return r.Operation == "unwrap" && len(r.Input) == 0 && len(r.Sealed.Reference) >= 1 && len(r.Sealed.Reference) <= 256 && len(r.Sealed.Ciphertext) >= 1 && len(r.Sealed.Ciphertext) <= 8192 && strings.HasPrefix(r.Sealed.Reference, "asservat-local-keyset/v1/"+r.Scope.InstallationID+"/"+r.Scope.Purpose+"/"+r.Scope.KeyID+"/")
}

// KeyRequestInfo contains no plaintext keyset. Binding remains
// available to the authority resolver to validate the canonical artifact/session
// purpose. RequestDigest binds every request field, including payload hashes.
type KeyRequestInfo struct {
	Scope                      KeyScope
	AuthorityID, Operation     string
	Reference                  string
	Binding                    []byte
	RequestDigest, InputDigest artifact.Digest
}

type KeyOperationPermit struct {
	AuthorityID, RecoveryEpoch string
	Revision                   uint64
	Certificate, RequestDigest artifact.Digest
	ObservedAt, ValidUntil     time.Time
}

func (p KeyOperationPermit) Valid(peer KeyPeer, request KeyRequestInfo, now time.Time) bool {
	return peer.Valid(now) && p.AuthorityID == request.AuthorityID && UUID(p.AuthorityID) && UUID(p.RecoveryEpoch) && p.Revision > 0 && p.Certificate == peer.Certificate && p.RequestDigest == request.RequestDigest && p.RequestDigest != (artifact.Digest{}) && identity.Fresh(p.ObservedAt, p.ValidUntil, now, 5*time.Second) && !p.ValidUntil.After(peer.NotAfter)
}

type KeyResult struct {
	Sealed        artifact.SealedKey
	Output        []byte
	RequestDigest artifact.Digest
	ValidUntil    time.Time
}

func (r KeyResult) Valid(operation string) bool {
	switch operation {
	case "wrap":
		return len(r.Output) == 0 && len(r.Sealed.Reference) >= 1 && len(r.Sealed.Reference) <= 256 && len(r.Sealed.Ciphertext) >= 1 && len(r.Sealed.Ciphertext) <= 8192
	case "unwrap":
		return r.Sealed == (artifact.SealedKey{}) && len(r.Output) >= 1 && len(r.Output) <= 4096
	}
	return false
}
