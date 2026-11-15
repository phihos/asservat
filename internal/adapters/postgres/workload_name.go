package postgres

import (
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// RememberWorkload records a resolved Deployment's or StatefulSet's kind and
// name by UID (ADR-335 D4). Evaluation matches an AccessBinding workload
// named without uid through this record; a UID never changes its name.
func (s *ContextPreviews) RememberWorkload(ctx context.Context, clusterID string, w cfg.WorkloadRef) error {
	if s == nil || !authorization.UUID(clusterID) || w.Kind != "Deployment" && w.Kind != "StatefulSet" || !identity.Text(w.Name, 253) || !identity.Text(w.UID, 64) {
		return cfg.ErrInvalid
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		return q.RememberWorkloadName(ctx, custodydb.RememberWorkloadNameParams{ClusterID: id(clusterID), WorkloadUid: w.UID, Ref: w.Kind + "/" + w.Name})
	})
}
