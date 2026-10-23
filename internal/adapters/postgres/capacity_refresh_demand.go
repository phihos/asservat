package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	capacity "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CapacityRefreshDemands are migration 00066's ADR-200 refresh demands for
// one permission root. The hub-api records them with its capture-preview
// credentials; the hub-worker reads them with its capacity writer role. A
// demand names an enrolled workload and confers no authority.
type CapacityRefreshDemands struct {
	ledger *Ledger
	root   string
}

func NewCapacityRefreshDemands(ctx context.Context, pool *pgxpool.Pool, root string) (*CapacityRefreshDemands, error) {
	if !authorization.UUID(root) {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &CapacityRefreshDemands{ledger: l, root: root}, nil
}

// DemandCapacityRefresh records or extends the demand; SQL ignores a workload
// that is not enrolled and ready.
func (s *CapacityRefreshDemands) DemandCapacityRefresh(ctx context.Context, r targets.Request) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !r.Valid() {
		return value.ErrUnavailable
	}
	call, end := context.WithTimeout(ctx, 2*time.Second)
	defer end()
	if err := custodydb.New(s.ledger.pool).DemandCapacityRefresh(call, custodydb.DemandCapacityRefreshParams{RootID: id(s.root), ClusterID: id(r.ClusterID),
		NamespaceUid: r.Namespace.UID, NamespaceName: r.Namespace.Name, WorkloadKind: r.Workload.Kind, WorkloadName: r.Workload.Name, WorkloadUid: r.Workload.UID}); err != nil {
		return value.ErrUnavailable
	}
	return nil
}

func (s *CapacityRefreshDemands) ReadCapacityRefreshDemands(ctx context.Context) ([]capacity.CapacityRefreshDemand, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, value.ErrUnavailable
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	raw, err := custodydb.New(s.ledger.pool).ReadCapacityRefreshDemands(call, id(s.root))
	if err != nil || len(raw) > 1<<16 {
		return nil, value.ErrUnavailable
	}
	var rows []struct {
		ClusterID, NamespaceUID, NamespaceName, Kind, Name, WorkloadUID string
		NotAfter                                                        time.Time
	}
	if strictJSON(string(raw), &rows) != nil || len(rows) > 16 {
		return nil, value.ErrUnavailable
	}
	now := time.Now()
	out := make([]capacity.CapacityRefreshDemand, 0, len(rows))
	for _, r := range rows {
		d := capacity.CapacityRefreshDemand{ClusterID: r.ClusterID, Namespace: cfg.NamespaceRef{Name: r.NamespaceName, UID: r.NamespaceUID},
			Workload: cfg.WorkloadRef{Kind: r.Kind, Name: r.Name, UID: r.WorkloadUID}, NotAfter: r.NotAfter}
		// A demand that expired in transit is skipped, not an error.
		if d.Valid(now) {
			out = append(out, d)
		}
	}
	return out, nil
}
