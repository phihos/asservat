package capture

import (
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

var ErrProcessingCoverage = errors.New("requested retention exceeds current processing backing")

// ProcessingCoverageRequest describes a proposed original capture. It is not
// a lineage node and cannot make an unpublished artifact readable.
type ProcessingCoverageRequest struct {
	RootID             string
	Location           artifact.Location
	Target             authorization.Target
	AnchorAt, DeleteBy time.Time
}

func (r ProcessingCoverageRequest) Valid() bool {
	return authorization.UUID(r.RootID) && r.Location.Validate() == nil && r.Target.Valid() && r.Target.ClusterID == r.Location.ClusterID &&
		!r.AnchorAt.IsZero() && r.AnchorAt.Nanosecond()%1000 == 0 && r.DeleteBy.Nanosecond()%1000 == 0 && r.DeleteBy.After(r.AnchorAt)
}

// ProcessingCoverage observes current prepaid coverage only. It neither
// reserves a lineage slot nor promises renewal or future publication. It is
// transient and never added to a reviewed approval digest or persisted intent.
type ProcessingCoverage struct {
	Request                ProcessingCoverageRequest
	ObservedAt, FreshUntil time.Time
}

func (o ProcessingCoverage) Current(now time.Time) bool {
	return o.Request.Valid() && !o.Request.AnchorAt.After(now) && identity.Fresh(o.ObservedAt, o.FreshUntil, now, 5*time.Second)
}
