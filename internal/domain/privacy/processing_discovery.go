package privacy

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ProcessingDiscoveryLimit bounds the scanned page and its audited response.
const ProcessingDiscoveryLimit = 12

type ProcessingDiscoveryCursor struct {
	AnchorAt   time.Time `json:"anchor_at,omitzero"`
	ArtifactID string    `json:"artifact_id"`
}

type ProcessingDiscoveryQuery struct {
	CaseID        string                    `json:"case_id,omitempty"`
	ClusterID     string                    `json:"cluster_id,omitempty"`
	NamespaceUID  string                    `json:"namespace_uid,omitempty"`
	WorkloadUID   string                    `json:"workload_uid,omitempty"`
	AcquiredFrom  time.Time                 `json:"acquired_from,omitzero"`
	AcquiredUntil time.Time                 `json:"acquired_until,omitzero"`
	PurposeRef    string                    `json:"purpose_ref,omitempty"`
	After         ProcessingDiscoveryCursor `json:"after,omitzero"`
	Limit         int                       `json:"limit"`
}

func (q ProcessingDiscoveryQuery) Valid() bool {
	if q.Limit < 1 || q.Limit > ProcessingDiscoveryLimit || q.PurposeRef != "" && !identity.Text(q.PurposeRef, 128) {
		return false
	}
	if q.CaseID != "" {
		return authorization.UUID(q.CaseID) && q.ClusterID == "" && q.NamespaceUID == "" && q.WorkloadUID == "" && q.AcquiredFrom.IsZero() && q.AcquiredUntil.IsZero() && q.validCursor(q.After)
	}
	scope := ProcessingScope{Kind: "workloadInterval", ClusterID: q.ClusterID, NamespaceUID: q.NamespaceUID, WorkloadUID: q.WorkloadUID, AcquiredFrom: q.AcquiredFrom, AcquiredUntil: q.AcquiredUntil}
	return scope.Valid() && q.validCursor(q.After)
}

func (q ProcessingDiscoveryQuery) validCursor(c ProcessingDiscoveryCursor) bool {
	if c.ArtifactID == "" {
		return c.AnchorAt.IsZero()
	}
	if !authorization.UUID(c.ArtifactID) {
		return false
	}
	if q.CaseID != "" {
		return c.AnchorAt.IsZero()
	}
	return !c.AnchorAt.IsZero() && c.AnchorAt.Nanosecond()%1000 == 0 && !c.AnchorAt.Before(q.AcquiredFrom) && c.AnchorAt.Before(q.AcquiredUntil)
}

func (c ProcessingDiscoveryCursor) after(other ProcessingDiscoveryCursor) bool {
	if c.AnchorAt.Equal(other.AnchorAt) {
		return c.ArtifactID > other.ArtifactID
	}
	return c.AnchorAt.After(other.AnchorAt)
}

type ProcessingDiscoveryCandidate struct {
	ArtifactID   string    `json:"artifact_id"`
	CaptureID    string    `json:"capture_id"`
	CaseID       string    `json:"case_id"`
	ClusterID    string    `json:"cluster_id"`
	NamespaceUID string    `json:"namespace_uid"`
	WorkloadUID  string    `json:"workload_uid"`
	PurposeRef   string    `json:"purpose_ref"`
	NativeType   string    `json:"native_type"`
	DataClass    string    `json:"data_class"`
	Origin       string    `json:"origin"`
	AnchorAt     time.Time `json:"anchor_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	DeleteBy     time.Time `json:"delete_by"`
	CustodyState string    `json:"custody_state"`
	Parents      []string  `json:"parents"`
}

func (r ProcessingDiscoveryCandidate) Valid() bool {
	name := r.NativeType
	if name == "podStatus" {
		name = artifact.PodStatusArtifact
	}
	typ, ok := artifact.LookupNativeType(name)
	if r.NativeType == "" || !ok || !typ.AllowsClass(r.DataClass) || !authorization.UUID(r.ArtifactID) || !authorization.UUID(r.CaptureID) || !authorization.UUID(r.CaseID) || !authorization.UUID(r.ClusterID) || !identity.Text(r.NamespaceUID, 64) || !identity.Text(r.WorkloadUID, 64) || !identity.Text(r.PurposeRef, 128) {
		return false
	}
	if r.AnchorAt.IsZero() || r.ExpiresAt.Before(r.AnchorAt) || r.DeleteBy.Before(r.ExpiresAt) || r.CustodyState != artifact.StoredUnpublished && r.CustodyState != artifact.Deleting {
		return false
	}
	if r.Parents == nil || len(r.Parents) > MaxProcessingParents || r.Origin == "capture" && len(r.Parents) != 0 || r.Origin == "derived" && len(r.Parents) == 0 || r.Origin != "capture" && r.Origin != "derived" {
		return false
	}
	seen := map[string]bool{r.ArtifactID: true}
	for _, id := range r.Parents {
		if !authorization.UUID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

type ProcessingDiscoveryPage struct {
	RootID, Epoch          string
	Sequence               int64
	ObservedAt, ValidUntil time.Time
	Candidates             []ProcessingDiscoveryCandidate
	Next                   ProcessingDiscoveryCursor
}

func (p ProcessingDiscoveryPage) Valid(q ProcessingDiscoveryQuery, now time.Time) bool {
	window := identity.Check(p.ObservedAt, identity.SQLFenced).Narrow(p.ValidUntil)
	if !q.Valid() || !authorization.UUID(p.RootID) || !authorization.UUID(p.Epoch) || p.Sequence < 1 || p.Sequence > 1<<60 || !window.Valid(now) || !window.Until().Equal(p.ValidUntil) || p.Candidates == nil || len(p.Candidates) > q.Limit || !q.validCursor(p.Next) {
		return false
	}
	last := q.After
	for _, r := range p.Candidates {
		if !r.Valid() || q.PurposeRef != "" && r.PurposeRef != q.PurposeRef {
			return false
		}
		cursor := ProcessingDiscoveryCursor{ArtifactID: r.ArtifactID}
		if q.CaseID != "" {
			if r.CaseID != q.CaseID {
				return false
			}
		} else {
			cursor.AnchorAt = r.AnchorAt
			if r.ClusterID != q.ClusterID || r.NamespaceUID != q.NamespaceUID || r.WorkloadUID != q.WorkloadUID || !q.validCursor(cursor) {
				return false
			}
		}
		if !cursor.after(last) {
			return false
		}
		last = cursor
	}
	// The continuation advances past scanned rows, including ones filtered out
	// by purpose or custody state. A page may contain no visible candidates.
	return p.Next.ArtifactID == "" || p.Next.after(q.After) && !last.after(p.Next)
}
