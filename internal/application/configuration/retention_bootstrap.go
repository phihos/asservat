package configuration

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/privacy"
)

// CheckInitialRetention checks the first complete LIST of a guarded source.
// Its policies are Kubernetes objects under the platform's RBAC (Helm renders
// the baseline), so they are accepted as listed; no separate installer review
// attests them. The coordinator must prove current protection around the read,
// persist acceptance and complete audit and retained-evidence reconciliation
// before making any source available.
func CheckInitialRetention(s privacy.PolicySnapshot, protection artifact.Digest, now time.Time) error {
	digest := RetentionSnapshotDigest(s)
	if !s.Valid(now) || protection == (artifact.Digest{}) || digest == (artifact.Digest{}) || s.Revision.UID != s.ControlNamespaceUID || s.Revision.Generation != 1 || s.Revision.Digest != digest {
		return value.ErrInvalid
	}
	return nil
}
