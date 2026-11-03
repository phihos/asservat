package authorization

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// RawQueryScopeBytes fixes canonical raw-query/v1 scope bytes. Typed validation
// and deterministic serialization stay separate, as for existing grant kinds.
func RawQueryScopeBytes(r value.RawQueryScope) ([]byte, artifact.Digest) {
	b, _ := json.Marshal(struct {
		Version string
		Scope   value.RawQueryScope
	}{"raw-query/v1", r})
	return b, sha256.Sum256(b)
}

// RawQueryScopeMatches binds the typed selected artifacts to the immutable
// bytes and digest. Both request composition and stored-row decoding use it.
func RawQueryScopeMatches(g value.Grant) bool {
	if g.Kind != value.GrantRawQuery || g.RawQuery == nil {
		return false
	}
	b, digest := RawQueryScopeBytes(*g.RawQuery)
	return bytes.Equal(b, g.Scope) && digest == g.ExecutionDigest
}
