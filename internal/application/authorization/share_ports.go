package authorization

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ShareReader is the recipient lookup of ADR-232: the caller's unrevoked,
// unexpired shares of exactly one artifact, keyed by the caller's own user
// and group keys. It reads no evidence and confers nothing by itself;
// value.EvaluateShare decides against the current permission projection.
type ShareReader interface {
	RecipientShares(ctx context.Context, artifactID string, caller identity.Identity) ([]value.Share, error)
}

// RecipientShare returns the first of rows that currently admits the caller
// to exactly this root, case, artifact and target (and, when version is set,
// this verified artifact version), with its EvaluateShare result. A current
// deny of the caller refuses every share.
func RecipientShare(i identity.Identity, p value.Projection, t value.Target, e *value.Retained, rows []value.Share, root, caseID, artifactID string, version artifact.Digest, now time.Time) (*value.Share, value.Result) {
	refused := value.Result{Reason: "NoEntitlement"}
	for _, s := range rows {
		if s.RootID != root || s.ArtifactID != artifactID || s.CaseID != caseID || s.Target != t || version != (artifact.Digest{}) && s.Version != version {
			continue
		}
		r := value.EvaluateShare(i, p, t, e, s, now)
		if r.Eligible {
			return &s, r
		}
		if r.Reason == "ExplicitDeny" {
			return nil, r
		}
		refused = r
	}
	return nil, refused
}

// SameShare finds the original share in a re-read and reports whether it is
// unchanged apart from its read interval (a revocation changes it).
func SameShare(a value.Share, rows []value.Share) (value.Share, bool) {
	for _, b := range rows {
		if b.ID == a.ID {
			return b, b.Revision == a.Revision && b.RevokedAt.Equal(a.RevokedAt) && b.ExpiresAt.Equal(a.ExpiresAt) && b.Version == a.Version && b.ArtifactID == a.ArtifactID && b.CaseID == a.CaseID && b.Target == a.Target
		}
	}
	return value.Share{}, false
}
