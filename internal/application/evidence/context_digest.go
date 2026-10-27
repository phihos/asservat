package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ContextExpectationDigest binds accepted control metadata, not native evidence.
func ContextExpectationDigest(e artifact.ContextExpectation) artifact.Digest {
	b, err := json.Marshal(e)
	if err != nil {
		return artifact.Digest{}
	}
	return artifact.Digest(sha256.Sum256(b))
}
func ContextCopiesDigest(c artifact.Copies) artifact.Digest {
	b, err := json.Marshal(c)
	if err != nil {
		return artifact.Digest{}
	}
	return artifact.Digest(sha256.Sum256(b))
}

// NativeETag is the strong opaque version validator of one immutable copy set
// (the same "v1-<copies digest>" form the pod-status download uses).
func NativeETag(version artifact.Digest) string { return `"v1-` + hex.EncodeToString(version[:]) + `"` }
