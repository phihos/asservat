package capture

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	"context"
	"testing"
	"time"
)

type inventoryCostPorts struct {
	*inventoryFixture
	eligibility, policies, workload int
}

func (p *inventoryCostPorts) ContextEligibilityCurrent(ctx context.Context, current identities.CurrentIdentity, target authorization.Target) authorization.CaptureEligibility {
	p.eligibility++
	return p.inventoryFixture.ContextEligibilityCurrent(ctx, current, target)
}
func (p *inventoryCostPorts) RecordingPolicy(ctx context.Context, name, uid string) (RecordingPolicy, error) {
	p.policies++
	return p.inventoryFixture.RecordingPolicy(ctx, name, uid)
}
func (p *inventoryCostPorts) WorkloadPermissions(ctx context.Context, target authorization.WorkloadTarget) (authorization.WorkloadProjection, error) {
	p.workload++
	return p.inventoryFixture.WorkloadPermissions(ctx, target)
}
func TestRecordingInventoryHundredRowComposedPortCost(t *testing.T) {
	x, s, target, current := newRecordingInventoryFixture(t, 100)
	p := &inventoryCostPorts{inventoryFixture: x}
	s.Eligibility, s.Policies, s.Permissions = p, p, p
	start := time.Now()
	first, err := s.List(t.Context(), current, target, "", "", 20)
	elapsed := time.Since(start)
	if err != nil || len(first.Rows) != 20 || p.eligibility != 200 || p.policies != 1 || p.workload != 3 || x.reads != 1 || x.writes != 1 {
		t.Fatal("unexpected bounded first-batch cost", err, p.eligibility, p.policies, p.workload, x.reads, x.writes)
	}
	t.Logf("synthetic in-memory first100 refs/20 visible: elapsed=%s eligibility=%d distinctPolicy=%d workload=%d candidateReads=%d selectionWrites=%d; excludes production SQL/Kubernetes latency", elapsed, p.eligibility, p.policies, p.workload, x.reads, x.writes)
	p.eligibility, p.policies, p.workload = 0, 0, 0
	start = time.Now()
	next, err := s.List(t.Context(), current, target, "", first.Cursor, 20)
	if err != nil || len(next.Rows) != 20 || p.eligibility != 40 || p.policies != 1 || p.workload != 3 || x.reads != 2 || x.writes != 1 {
		t.Fatal("within-set page rescanned full batch", err, p.eligibility, p.policies, p.workload, x.reads, x.writes)
	}
	t.Logf("synthetic in-memory next20: elapsed=%s eligibility=%d distinctPolicy=%d workload=%d exactSourceReads=1 additionalSelectionWrites=0; excludes production SQL/Kubernetes latency", time.Since(start), p.eligibility, p.policies, p.workload)
}
