package audit

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// RetentionAcceptance records configuration identities and continuity, not
// workload labels, free-text policy purposes or captured user data.
type RetentionAcceptance struct {
	ID, RootID, Epoch, SourceClusterID, ControlNamespaceUID string
	Hub                                                     bool
	Sequence                                                int64
	ProtectionDigest, CheckpointDigest, PreviousDigest      artifact.Digest
	CreatedAt                                               time.Time
	Policies                                                []artifact.RetentionRule
	Bootstrap                                               *RetentionBootstrap
}
type RetentionBootstrap struct {
	PoliciesDigest                     artifact.Digest
	PolicyCount                        int
	ReviewUID, ReviewVersion, Reviewer string
	ReviewDigest                       artifact.Digest
	ReviewedAt, ExpiresAt              time.Time
}

func (r RetentionAcceptance) Valid() bool {
	if !authorization.UUID(r.ID) || !authorization.UUID(r.RootID) || !authorization.UUID(r.Epoch) || !authorization.UUID(r.SourceClusterID) || !identity.Text(r.ControlNamespaceUID, 64) || r.Sequence < 1 || r.Sequence > 2147483647 || r.ProtectionDigest == (artifact.Digest{}) || r.CheckpointDigest == (artifact.Digest{}) || r.CreatedAt.IsZero() || len(r.Policies) > 1024 || (r.Sequence == 1) != (r.PreviousDigest == (artifact.Digest{})) {
		return false
	}
	previous := ""
	for _, p := range r.Policies {
		if !identity.Text(p.UID, 64) || p.UID <= previous || p.Generation < 1 || p.Generation > 2147483647 || p.Digest == (artifact.Digest{}) {
			return false
		}
		previous = p.UID
	}
	if (r.Sequence == 1) != (r.Bootstrap != nil) {
		return false
	}
	if b := r.Bootstrap; b != nil {
		if b.PoliciesDigest == (artifact.Digest{}) || b.PolicyCount != len(r.Policies) {
			return false
		}
		if b.PolicyCount == 0 {
			return b.ReviewUID == "" && b.ReviewVersion == "" && b.Reviewer == "" && b.ReviewDigest == (artifact.Digest{}) && b.ReviewedAt.IsZero() && b.ExpiresAt.IsZero()
		}
		if !identity.Text(b.ReviewUID, 64) || !identity.Text(b.ReviewVersion, 128) || !identity.Text(b.Reviewer, 256) || b.ReviewDigest == (artifact.Digest{}) || !identity.Fresh(b.ReviewedAt, b.ExpiresAt, r.CreatedAt, time.Hour) {
			return false
		}
	}
	return true
}
func RetentionAcceptanceKey(root, event string) string {
	return "retention-acceptance/v1/" + root + "/" + event + "/record"
}
func (r Receipt) ValidRetentionAcceptance(root, event string) bool {
	return authorization.UUID(root) && authorization.UUID(event) && r.Key == RetentionAcceptanceKey(root, event) && r.Version != "null" && identity.Text(r.Version, 1024) && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= 512<<10 && r.SHA256 != (artifact.Digest{})
}

// HistoricalRetentionAcceptance preserves structural replay and restrictive
// catch-up of an original receipt. It grants no current source/effect authority.
func (r Receipt) HistoricalRetentionAcceptance(root, event string) bool {
	return authorization.UUID(root) && authorization.UUID(event) && r.Key == RetentionAcceptanceKey(root, event) && (r.Version == "" || identity.Text(r.Version, 1024)) && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= 512<<10 && r.SHA256 != (artifact.Digest{})
}
