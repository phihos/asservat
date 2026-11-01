package planning

import (
	"crypto/sha256"
	"encoding/json"
	"slices"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
)

// SourceAudienceDigest binds the complete initial source audience, independently
// of contributing ownership assignments. Order cannot change its meaning.
func SourceAudienceDigest(audience []artifact.AudienceAssignment) (artifact.Digest, error) {
	if len(audience) < 1 || len(audience) > 32 {
		return artifact.Digest{}, value.ErrInvalid
	}
	refs := slices.Clone(audience)
	slices.SortFunc(refs, func(a, b artifact.AudienceAssignment) int {
		if a.AssignmentID < b.AssignmentID {
			return -1
		}
		if a.AssignmentID > b.AssignmentID {
			return 1
		}
		return 0
	})
	for n, a := range refs {
		if !authorization.UUID(a.AssignmentID) || !identity.Text(a.Kind, 16) || !identity.Text(a.Issuer, 2048) || !identity.Text(a.SubjectID, 256) || !identity.Text(a.Role, 32) || !identity.Text(a.BasisKind, 32) || !identity.Text(a.BasisUID, 64) || a.BasisDigest == (artifact.Digest{}) || n > 0 && refs[n-1].AssignmentID == a.AssignmentID {
			return artifact.Digest{}, value.ErrInvalid
		}
	}
	raw, err := json.Marshal(refs)
	if err != nil {
		return artifact.Digest{}, err
	}
	return artifact.Digest(sha256.Sum256(raw)), nil
}
