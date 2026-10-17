package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"crypto/sha256"
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
