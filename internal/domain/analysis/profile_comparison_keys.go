package analysis

import (
	"crypto/sha1"
	"fmt"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ProfileComparisonKeyChildIDs names two independently spent children. UUIDs
// locate rows only; exact stored parents, mTLS and current checks grant use.
// The fixed versioned namespace makes hub assembly and binding agree without
// another lookup, randomness requirement or caller-chosen source ordinal.
func ProfileComparisonKeyChildIDs(batch string) ([2]string, error) {
	var out [2]string
	if !authorization.UUID(batch) {
		return out, ErrInvalid
	}
	var parsed [16]byte
	raw := strings.ReplaceAll(batch, "-", "")
	for j := range parsed {
		parsed[j] = byte(strings.IndexByte("0123456789abcdef", raw[2*j])<<4 | strings.IndexByte("0123456789abcdef", raw[2*j+1]))
	}
	// RFC4122 OID namespace, followed by our versioned namespace name.
	namespace := comparisonNameUUID([16]byte{0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}, []byte("asservat/profile-comparison-key-child/v1"))
	for ordinal := range out {
		name := append(append([]byte{}, parsed[:]...), byte(ordinal))
		child := comparisonNameUUID(namespace, name)
		out[ordinal] = fmt.Sprintf("%x-%x-%x-%x-%x", child[:4], child[4:6], child[6:8], child[8:10], child[10:])
		if out[ordinal] == batch {
			return [2]string{}, ErrInvalid
		}
	}
	if out[0] == out[1] {
		return [2]string{}, ErrInvalid
	}
	return out, nil
}

// comparisonNameUUID is RFC4122 version5 for non-authority value identities.
func comparisonNameUUID(namespace [16]byte, name []byte) [16]byte {
	h := sha1.New()
	_, _ = h.Write(namespace[:])
	_, _ = h.Write(name)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	out[6] = (out[6] & 0x0f) | 0x50
	out[8] = (out[8] & 0x3f) | 0x80
	return out
}

// ContextProjectionComparisonKeyChild pins one of two independent three-role
// children to existing immutable query, batch, authority and worker parents.
// It carries no duplicate query/authority or independent disclosure permit.
type ContextProjectionComparisonKeyChild struct {
	ID, QueryID, BatchID, WorkerID, ProcessEpoch           string
	SourceOrdinal                                          int
	SourceVersion, AuthorityDigest, PublicKey, Certificate artifact.Digest
	Scope                                                  authorization.KeyScope
	CreatedAt, Until                                       time.Time
}

func (c ContextProjectionComparisonKeyChild) Valid(q ContextQuery, b ContextReadBatch, a ContextProjectionAuthority, now time.Time) bool {
	ids, err := ProfileComparisonKeyChildIDs(b.ID)
	if err != nil || c.SourceOrdinal < 0 || c.SourceOrdinal > 1 || c.ID != ids[c.SourceOrdinal] || q.Scope.Comparison == (ProfileComparisonWindow{}) || !b.Current(q, a, now) || c.QueryID != q.ID || c.BatchID != b.ID || c.WorkerID != q.WorkerID || c.ProcessEpoch != b.Worker.ProcessEpoch || c.PublicKey == (artifact.Digest{}) || c.Certificate != b.Worker.Certificate || c.AuthorityDigest != a.DecisionDigest || !c.Scope.Valid() || c.Scope.Purpose != "artifact" || c.Scope.InstallationID != q.Plan.InstallationID || !identity.Fresh(c.CreatedAt, c.Until, now, identity.EvidenceReadRequestWindow) || c.CreatedAt.Before(b.StartedAt) || c.Until.After(b.Until) || c.Until.After(a.ValidUntil) || c.Until.After(q.ProviderUntil) {
		return false
	}
	switch c.SourceOrdinal {
	case 0:
		return c.SourceVersion == q.Scope.Comparison.Baseline.Version
	case 1:
		return c.SourceVersion == q.Scope.Version
	}
	return false
}
