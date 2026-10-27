package postgres

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"slices"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

// PreviewProjections reads, in one transaction under the shared permission
// stream lock, the accepted projection of every workload scope cell of the
// requested namespaces (ADR-237). A namespace's cells are the workload UIDs
// that any current basis or the proposal names, plus one cell for all other
// workloads. Each cell uses the same permissionProjection as the capture and
// read paths; an unavailable or oversized projection marks only that cell.
// It reads no catalog, evidence or group membership and writes nothing.
func (p *Permissions) PreviewProjections(ctx context.Context, r cfg.PreviewRead) (cfg.PreviewSnapshot, error) {
	var out cfg.PreviewSnapshot
	err := p.transaction(ctx, func(q *custodydb.Queries) error {
		s, err := q.SharePermissionStream(ctx, id(p.root))
		if err != nil {
			return err
		}
		out.Revision = identity.Revision{UID: uid(s.Epoch), Generation: s.Sequence}
		copy(out.Revision.Digest[:], s.ProjectionDigest)
		bases, err := q.ListPermissionBases(ctx, s.ID)
		if err != nil {
			return err
		}
		if len(bases) > 1024 {
			return cfg.ErrLimit
		}
		namespaces := slices.Clone(r.Namespaces)
		named := map[cfg.PreviewNamespace][]string{}
		for ns, workloads := range r.Workloads {
			named[ns] = slices.Clone(workloads)
		}
		for _, ref := range r.Bases {
			found := false
			for _, b := range bases {
				ns := cfg.PreviewNamespace{ClusterID: uid(b.ClusterID), NamespaceUID: b.NamespaceUid}
				// A delegated previewer's read matches objects only inside
				// their envelope namespaces; elsewhere they look nonexistent.
				if b.Kind != ref.Kind || b.Uid != ref.UID || r.Allowed != nil && !slices.Contains(r.Allowed, ns) {
					continue
				}
				found = true
				if !slices.Contains(namespaces, ns) {
					namespaces = append(namespaces, ns)
				}
			}
			if !found {
				out.Unmatched = append(out.Unmatched, ref)
			}
		}
		// ADR-242: proposed sources are evaluated against the namespace
		// observation of the current accepted batch, and the namespaces they
		// grant join the cells read.
		if len(r.Sources) > 0 {
			observation, err := currentNamespaceObservation(ctx, q, s)
			if err != nil {
				return err
			}
			for _, src := range r.Sources {
				if _, why := cfg.ReviewSourceFor(src); why == "" {
					out.Sources = append(out.Sources, cfg.PreviewSourceGrants{Unevaluated: cfg.DecisionTimeSource})
					continue
				}
				grants, reason := configapp.NamespaceGrants(src, "", observation)
				switch reason {
				case cfg.MetadataUnavailable, cfg.MetadataNotObserved:
					out.Sources = append(out.Sources, cfg.PreviewSourceGrants{Unevaluated: reason})
					continue
				}
				out.Sources = append(out.Sources, cfg.PreviewSourceGrants{Grants: grants})
				for _, g := range grants {
					if ns := (cfg.PreviewNamespace{ClusterID: src.ClusterID, NamespaceUID: g.Namespace.UID}); !slices.Contains(namespaces, ns) {
						namespaces = append(namespaces, ns)
					}
				}
			}
		}
		for _, b := range bases {
			ns := cfg.PreviewNamespace{ClusterID: uid(b.ClusterID), NamespaceUID: b.NamespaceUid}
			if !slices.Contains(namespaces, ns) {
				continue
			}
			for _, w := range b.WorkloadUids {
				if w == cfg.OtherWorkloads {
					return cfg.ErrInvalid
				}
				if !slices.Contains(named[ns], w) {
					named[ns] = append(named[ns], w)
				}
			}
		}
		slices.SortFunc(namespaces, func(a, b cfg.PreviewNamespace) int {
			return cmp.Or(cmp.Compare(a.ClusterID, b.ClusterID), cmp.Compare(a.NamespaceUID, b.NamespaceUID))
		})
		cells := 0
		for _, ns := range namespaces {
			cells += len(named[ns]) + 1
		}
		if cells > cfg.MaxPreviewTargets {
			return cfg.ErrLimit
		}
		for _, ns := range namespaces {
			workloads := slices.Sorted(slices.Values(named[ns]))
			for _, w := range append(workloads, cfg.OtherWorkloads) {
				target := authorization.Target{ClusterID: ns.ClusterID, NamespaceUID: ns.NamespaceUID, WorkloadUID: w, PodUID: w}
				cell := cfg.PreviewCell{Target: target}
				projection, err := permissionProjection(ctx, q, s, target)
				switch {
				case err == nil:
					cell.Projection = projection
				case errors.Is(err, cfg.ErrUnavailable):
					cell.Unavailable = authorization.UnmetPermissionStale
				case errors.Is(err, cfg.ErrLimit):
					cell.Unavailable = authorization.UnmetServiceUnavailable
				default:
					return err
				}
				out.Cells = append(out.Cells, cell)
			}
		}
		return nil
	})
	if err != nil {
		return cfg.PreviewSnapshot{}, err
	}
	return out, nil
}

// currentNamespaceObservation returns the namespace observation of the
// stream's current acceptance, or nil when the stream is not current or that
// acceptance holds none (ADR-242). Identical refreshes keep the stream's
// sequence, so a current stream's observation is the current one.
func currentNamespaceObservation(ctx context.Context, q *custodydb.Queries, s custodydb.PermissionStream) (*cfg.NamespaceObservation, error) {
	n, err := q.CurrentTime(ctx)
	if err != nil {
		return nil, err
	}
	if !s.InitialAuditID.Valid || s.Suspended || s.Sequence < 1 || !n.Time.Before(s.LeaseUntil.Time) || !identity.Fresh(s.ObservedAt.Time, s.FreshUntil.Time, n.Time, authorization.PermissionObservationInterval) {
		return nil, nil
	}
	raw, err := q.ReadPermissionChangeRecord(ctx, custodydb.ReadPermissionChangeRecordParams{StreamID: s.ID, Epoch: s.Epoch, Sequence: s.Sequence})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record struct{ Namespaces *cfg.NamespaceObservation }
	if json.Unmarshal(raw, &record) != nil || record.Namespaces != nil && !record.Namespaces.Valid() {
		return nil, cfg.ErrUnavailable
	}
	return record.Namespaces, nil
}
