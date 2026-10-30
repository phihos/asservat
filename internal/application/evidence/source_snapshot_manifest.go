package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"crypto/sha256"
	"encoding/json"
)

// ValidSourceSnapshotManifest validates independently accepted source documents
// before key preparation, native validation and encrypted manifest processing.
func ValidSourceSnapshotManifest(e artifact.ContextExpectation) bool {
	m := e.SourceSnapshotManifest
	if e.Snapshot == nil {
		return m == nil
	}
	return m.Valid() && json.Valid(m.CanonicalScope) && json.Valid(m.Binding) && artifact.Digest(sha256.Sum256(m.CanonicalScope)) == e.PlanDigest && artifact.Digest(sha256.Sum256(m.Binding)) == e.Snapshot.SourceBindingDigest
}
