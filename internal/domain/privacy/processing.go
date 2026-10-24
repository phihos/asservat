package privacy

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const MaxProcessingAncestors = 64
const MaxProcessingParents = 16
const MaxProcessingRules = 1024

// ProcessingScope uses immutable catalog identities and original acquisition
// times. A workload/time rule therefore also covers later-published matches;
// it is not an asynchronously copied flag on today's artifacts.
type ProcessingScope struct {
	Kind                                 string
	Location                             artifact.Location
	ClusterID, NamespaceUID, WorkloadUID string
	AcquiredFrom, AcquiredUntil          time.Time
}

func (s ProcessingScope) Valid() bool {
	switch s.Kind {
	case "artifact":
		return s.Location.Validate() == nil && s.ClusterID == "" && s.NamespaceUID == "" && s.WorkloadUID == "" && s.AcquiredFrom.IsZero() && s.AcquiredUntil.IsZero()
	case "workloadInterval":
		return s.Location == (artifact.Location{}) && authorization.UUID(s.ClusterID) && identity.Text(s.NamespaceUID, 64) && identity.Text(s.WorkloadUID, 64) && !s.AcquiredFrom.IsZero() && s.AcquiredUntil.After(s.AcquiredFrom) && s.AcquiredUntil.Sub(s.AcquiredFrom) <= 3660*24*time.Hour && s.AcquiredFrom.Nanosecond()%1000 == 0 && s.AcquiredUntil.Nanosecond()%1000 == 0
	default:
		return false
	}
}

// A node is supplied by the verified publication/lineage facet. A fresh artifact
// ID, no matching restriction row, or an absent parent is never proof of a root.
type ProcessingNode struct {
	CaptureID                    string
	Location                     artifact.Location
	Target                       authorization.Target
	AnchorAt, DeleteBy, RetireBy time.Time
	Origin                       string
	Parents                      []artifact.Location
}

func (n ProcessingNode) Valid() bool {
	if !authorization.UUID(n.CaptureID) || n.Location.Validate() != nil || !n.Target.Valid() || n.Target.ClusterID != n.Location.ClusterID || n.AnchorAt.IsZero() || !n.DeleteBy.After(n.AnchorAt) || !n.RetireBy.After(n.DeleteBy) || n.Parents == nil || len(n.Parents) > MaxProcessingParents {
		return false
	}
	if n.Origin == "capture" && len(n.Parents) != 0 || n.Origin == "derived" && len(n.Parents) == 0 || n.Origin != "capture" && n.Origin != "derived" {
		return false
	}
	seen := map[artifact.Location]bool{}
	for _, p := range n.Parents {
		if p.Validate() != nil || p == n.Location || seen[p] {
			return false
		}
		seen[p] = true
	}
	return true
}
func (s ProcessingScope) Matches(n ProcessingNode) bool {
	if !s.Valid() || !n.Valid() {
		return false
	}
	if s.Kind == "artifact" {
		return s.Location == n.Location
	}
	return s.ClusterID == n.Target.ClusterID && s.NamespaceUID == n.Target.NamespaceUID && s.WorkloadUID == n.Target.WorkloadUID && !n.AnchorAt.Before(s.AcquiredFrom) && n.AnchorAt.Before(s.AcquiredUntil)
}

type ProcessingRule struct {
	ID                            string
	Revision                      int64
	Scope                         ProcessingScope
	State                         string
	ReleaseAcknowledged           bool
	AdministrationUntil, RetireBy time.Time
}

func (r ProcessingRule) Valid() bool {
	return !r.AdministrationUntil.IsZero() && r.RetireBy.After(r.AdministrationUntil) && authorization.UUID(r.ID) && r.Revision > 0 && r.Revision <= 16 && r.Scope.Valid() && (r.State == "restricted" && !r.ReleaseAcknowledged || r.State == "releasePending" && !r.ReleaseAcknowledged || r.State == "released" && r.ReleaseAcknowledged)
}

// Complete is established by the durable accepted root plus exact bounded SQL
// lineage traversal, never by observing an empty current result. These values
// alone are not a permission; the application also checks policy and recovery.
type ProcessingSnapshot struct {
	RootID, Epoch          string
	Sequence               int64
	Complete               bool
	Subject                artifact.Location
	Nodes                  []ProcessingNode
	Rules                  []ProcessingRule
	ObservedAt, FreshUntil time.Time
}

// Allows admits a snapshot current for at most the evidence-read window:
// approved-query reads observe processing over their 20 s evidence and
// recovery observations (installed native81); download and capture producers
// keep their five-second inputs.
func (s ProcessingSnapshot) Allows(now time.Time) bool {
	if !authorization.UUID(s.RootID) || !authorization.UUID(s.Epoch) || s.Sequence < 1 || s.Sequence > 1<<60 || !s.Complete || s.Subject.Validate() != nil || len(s.Nodes) < 1 || len(s.Nodes) > MaxProcessingAncestors || s.Rules == nil || len(s.Rules) > MaxProcessingRules || !identity.Fresh(s.ObservedAt, s.FreshUntil, now, identity.EvidenceReadRequestWindow) {
		return false
	}
	nodes := map[artifact.Location]ProcessingNode{}
	for _, n := range s.Nodes {
		if !n.Valid() {
			return false
		}
		if _, ok := nodes[n.Location]; ok {
			return false
		}
		nodes[n.Location] = n
	}
	visited := map[artifact.Location]bool{}
	active := map[artifact.Location]bool{}
	var visit func(artifact.Location) bool
	visit = func(loc artifact.Location) bool {
		if active[loc] {
			return false
		}
		if visited[loc] {
			return true
		}
		n, ok := nodes[loc]
		if !ok {
			return false
		}
		active[loc] = true
		for _, parent := range n.Parents {
			if !visit(parent) {
				return false
			}
		}
		delete(active, loc)
		visited[loc] = true
		return true
	}
	if !visit(s.Subject) || len(visited) != len(nodes) {
		return false
	}
	seen := map[string]bool{}
	for _, r := range s.Rules {
		if !r.Valid() || seen[r.ID] {
			return false
		}
		seen[r.ID] = true
		// Administrative/backing expiry never releases a restriction. These
		// immutable dates are history bounds, not an allow-until condition.
		if r.State == "released" {
			continue
		}
		for _, n := range s.Nodes {
			if r.Scope.Matches(n) {
				return false
			}
		}
	}
	return true
}
