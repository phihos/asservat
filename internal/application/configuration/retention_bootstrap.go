package configuration

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/privacy"
)

type RetentionBootstrapReviewReader interface {
	InitialRetentionReview(context.Context) (value.RetentionBootstrapReview, error)
}

// This only checks the initial value attestation. The coordinator must prove
// current protection around the read, persist acceptance and complete audit and
// retained-evidence reconciliation before making any source available.
func CheckInitialRetention(s privacy.PolicySnapshot, protection artifact.Digest, r *value.RetentionBootstrapReview, now time.Time) error {
	digest := RetentionSnapshotDigest(s)
	if !s.Valid(now) || protection == (artifact.Digest{}) || digest == (artifact.Digest{}) || s.Revision.UID != s.ControlNamespaceUID || s.Revision.Generation != 1 || s.Revision.Digest != digest {
		return value.ErrInvalid
	}
	if len(s.Policies) == 0 {
		return nil
	}
	if r == nil || !r.Valid(now) || r.Resource.ClusterID != s.SourceClusterID || r.Resource.NamespaceUID != s.ControlNamespaceUID || r.PoliciesDigest != digest || r.ProtectionDigest != protection {
		return value.ErrDenied
	}
	return nil
}
