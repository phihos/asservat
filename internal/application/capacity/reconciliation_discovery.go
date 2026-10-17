package capacity

import (
	"context"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// This cursor contains candidate metadata only, never an authority observation
// or a durable job. One turn does at most one LIST or returns one candidate.
// Each cluster retains at most one 64-entry namespace/workload page; advancing
// round-robin before effects prevents one unavailable scope starving another.
type capacityDiscoveryCursor struct {
	namespaces                 []cfg.NamespaceRef
	namespaceIndex, kindIndex  int
	namespaceNext, namespaceRV string
	namespacePageLoaded        bool
	workloads                  []cfg.WorkloadRef
	workloadIndex              int
	workloadNext, workloadRV   string
	workloadPageLoaded         bool
}

var capacityWorkloadKinds = [...]string{"Deployment", "StatefulSet", "Pod"}

func capacityDiscoveryPageValid(rv, next, requested, prior string, count int) bool {
	return identity.Text(rv, 128) && count <= CapacityDiscoveryPageSize && len(next) <= 8192 &&
		(next == "" || next != requested) && (requested == "" || rv == prior)
}

func (s *capacityDiscoveryCursor) resetWorkloads() {
	s.workloads, s.workloadIndex, s.workloadNext, s.workloadRV, s.workloadPageLoaded = nil, 0, "", "", false
}

// pending reports whether next yields a candidate without any I/O.
func (s *capacityDiscoveryCursor) pending() bool {
	return s.namespaceIndex < len(s.namespaces) && s.workloadIndex < len(s.workloads)
}

func (s *capacityDiscoveryCursor) next(ctx context.Context, reader CapacityWorkloadReader) (cfg.NamespaceRef, cfg.WorkloadRef, bool, error) {
	var ns cfg.NamespaceRef
	var candidate cfg.WorkloadRef
	if ctx == nil || ctx.Err() != nil || reader == nil {
		return ns, candidate, false, cfg.ErrUnavailable
	}
	if s.namespaceIndex >= len(s.namespaces) {
		if s.namespacePageLoaded && s.namespaceNext == "" {
			*s = capacityDiscoveryCursor{}
		}
		page, err := reader.DiscoverCapacityNamespaces(ctx, s.namespaceNext)
		if err != nil || ctx.Err() != nil || !capacityDiscoveryPageValid(page.ResourceVersion, page.Continue, s.namespaceNext, s.namespaceRV, len(page.Namespaces)) {
			*s = capacityDiscoveryCursor{}
			return ns, candidate, false, cfg.ErrUnavailable
		}
		seen := map[string]bool{}
		for _, v := range page.Namespaces {
			if !identity.Text(v.Name, 63) || !identity.Text(v.UID, 64) || seen[v.UID] {
				*s = capacityDiscoveryCursor{}
				return ns, candidate, false, cfg.ErrUnavailable
			}
			seen[v.UID] = true
		}
		s.namespaces, s.namespaceIndex, s.kindIndex = append([]cfg.NamespaceRef(nil), page.Namespaces...), 0, 0
		s.namespaceNext, s.namespaceRV, s.namespacePageLoaded = page.Continue, page.ResourceVersion, true
		s.resetWorkloads()
		return ns, candidate, false, nil
	}
	ns = s.namespaces[s.namespaceIndex]
	if s.workloadIndex < len(s.workloads) {
		candidate = s.workloads[s.workloadIndex]
		s.workloadIndex++ // A failed exact read does not pin this candidate forever.
		return ns, candidate, true, nil
	}
	if s.workloadPageLoaded && s.workloadNext == "" {
		s.resetWorkloads()
		s.kindIndex++
		if s.kindIndex == len(capacityWorkloadKinds) {
			s.kindIndex = 0
			s.namespaceIndex++
			return cfg.NamespaceRef{}, candidate, false, nil
		}
	}
	kind := capacityWorkloadKinds[s.kindIndex]
	page, err := reader.DiscoverCapacityWorkloads(ctx, ns, kind, s.workloadNext)
	if err != nil || ctx.Err() != nil || !capacityDiscoveryPageValid(page.ResourceVersion, page.Continue, s.workloadNext, s.workloadRV, len(page.Workloads)) {
		// Skip this kind for this pass, then continue other kinds/namespaces.
		// The next complete enumeration starts from an empty continuation.
		s.resetWorkloads()
		s.workloadPageLoaded = true
		return ns, candidate, false, cfg.ErrUnavailable
	}
	seen := map[string]bool{}
	for _, v := range page.Workloads {
		if v.Kind != kind || !identity.Text(v.Name, 253) || !identity.Text(v.UID, 64) || seen[v.UID] {
			s.resetWorkloads()
			s.workloadPageLoaded = true
			return ns, candidate, false, cfg.ErrUnavailable
		}
		seen[v.UID] = true
	}
	s.workloads, s.workloadIndex = append([]cfg.WorkloadRef(nil), page.Workloads...), 0
	s.workloadNext, s.workloadRV, s.workloadPageLoaded = page.Continue, page.ResourceVersion, true
	return ns, candidate, false, nil
}
