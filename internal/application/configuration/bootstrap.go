package configuration

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
)

type BootstrapReviewReader interface {
	InitialPermissionReview(context.Context) (value.BootstrapReview, error)
}

// InitialBindingDigest is a reviewed complete explicit-binding snapshot. Status
// and unrelated metadata do not force another review. Replacement UIDs and any
// spec change do. It cannot stand in for subsequent assignment continuity.
func InitialBindingDigest(s value.Snapshot) artifact.Digest {
	type row struct {
		UID  string
		Spec artifact.Digest
	}
	rows := make([]row, 0, len(s.Bindings))
	for _, b := range s.Bindings {
		rows = append(rows, row{b.Resource.UID, b.Resource.SpecDigest})
	}
	slices.SortFunc(rows, func(a, b row) int { return cmp.Compare(a.UID, b.UID) })
	encoded, _ := json.Marshal(struct {
		Cluster  string
		Control  value.NamespaceRef
		Bindings []row
	}{s.ClusterID, s.ControlNamespace, rows})
	return artifact.Digest(sha256.Sum256(encoded))
}

// CheckInitialBindings is a one-time prerequisite for pre-existing explicit
// configuration. Empty installations can establish their first guarded baseline
// without a review of nonexistent values. Reconciliation still checks the live
// guard before and after reading; installing a guard alone authenticates no past.
func CheckInitialBindings(s value.Snapshot, r *value.BootstrapReview, now time.Time) error {
	if len(s.Bindings) == 0 {
		return nil
	}
	if r == nil || !r.Valid(now) || r.Resource.ClusterID != s.ClusterID || r.Resource.Namespace != s.ControlNamespace.Name || r.Resource.NamespaceUID != s.ControlNamespace.UID || r.BindingsDigest != InitialBindingDigest(s) {
		return value.ErrDenied
	}
	return nil
}
