package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	value "asservat.local/asservat/internal/domain/analysis"
)

const comparisonQueryBytes = 96 << 10
const comparisonAuthorityBytes = 128 << 10

func projectionQueryBytes(q value.ContextQuery) int {
	if q.Scope.Comparison != (value.ProfileComparisonWindow{}) {
		return comparisonQueryBytes
	}
	return 64 << 10
}
func projectionAuthorityBytes(a value.ContextProjectionAuthority) int {
	if a.Scope.Comparison != (value.ProfileComparisonWindow{}) {
		return comparisonAuthorityBytes
	}
	return 64 << 10
}

// The pair remains intact on the outer transaction. These owned single-source
// views reuse the exact existing backing, publication and retention fences.
func projectionQuerySource(q value.ContextQuery, a value.ContextProjectionAuthority, baseline bool) (value.ContextQuery, value.ContextProjectionAuthority) {
	if q.Scope.Comparison == (value.ProfileComparisonWindow{}) {
		return q, a
	}
	if baseline {
		q.Scope, _ = q.Scope.BaselineScope()
		q.Plan = q.BaselinePlan
		if a.Baseline == nil {
			return value.ContextQuery{}, value.ContextProjectionAuthority{}
		}
		a = *a.Baseline
	} else {
		q.Scope, _ = q.Scope.IncidentScope()
		a.Scope = q.Scope
		a.Baseline = nil
	}
	q.BaselinePlan = value.ContextQueryPlan{}
	return q, a
}
func projectionAdmissionPlansCurrent(q value.ContextQuery, now time.Time) bool {
	if q.Scope.Comparison == (value.ProfileComparisonWindow{}) {
		return q.BaselinePlan == (value.ContextQueryPlan{}) && q.Plan.Valid(q.Scope, now)
	}
	b, bok := q.Scope.BaselineScope()
	i, iok := q.Scope.IncidentScope()
	return bok && iok && value.ProfileComparisonPlansMatch(q.Scope, q.BaselinePlan, q.Plan) && q.BaselinePlan.Valid(b, now) && q.Plan.Valid(i, now)
}
func lockProjectionAllocations(ctx context.Context, tx *custodydb.Queries, q value.ContextQuery) (custodydb.ContextQueryAllocation, custodydb.ContextQueryAllocation, error) {
	ids := []string{q.Plan.AllocationID}
	if q.Scope.Comparison != (value.ProfileComparisonWindow{}) && q.BaselinePlan.AllocationID != q.Plan.AllocationID {
		ids = append(ids, q.BaselinePlan.AllocationID)
		if ids[1] < ids[0] {
			ids[0], ids[1] = ids[1], ids[0]
		}
	}
	var incident, baseline custodydb.ContextQueryAllocation
	for _, v := range ids {
		row, e := tx.LockContextQueryAllocation(ctx, custodydb.LockContextQueryAllocationParams{ID: id(v), RootID: id(q.Scope.RootID)})
		if e != nil {
			return incident, baseline, e
		}
		if v == q.Plan.AllocationID {
			incident = row
		}
		if v == q.BaselinePlan.AllocationID {
			baseline = row
		}
	}
	return incident, baseline, nil
}
