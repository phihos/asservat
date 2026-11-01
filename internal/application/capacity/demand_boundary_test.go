package capacity

import (
	"context"
	"errors"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

type demandReadFunc func(context.Context) ([]CapacityRefreshDemand, error)

func (f demandReadFunc) ReadCapacityRefreshDemands(ctx context.Context) ([]CapacityRefreshDemand, error) {
	return f(ctx)
}

// These are explicit diagnostic-boundary fixtures, not evidence of the Native
// demand reader's outcome or a cold-readiness availability correction.
func TestCapacityDemandBoundaryReportsReadAndClusterFailures(t *testing.T) {
	for _, mode := range []string{"read", "read-deadline", "cluster-unmatched", "empty"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			original, _ := ctx.Deadline()
			reads := 0
			runner := CapacityReconciler{Work: &CapacityWorkReconciler{Now: time.Now}}
			runner.Demands = demandReadFunc(func(call context.Context) ([]CapacityRefreshDemand, error) {
				reads++
				if until, ok := call.Deadline(); !ok || until.After(original) {
					t.Fatal("demand read extended original owner")
				}
				switch mode {
				case "read":
					return nil, errors.New("synthetic private provider secret")
				case "read-deadline":
					<-call.Done()
					return nil, nil
				case "cluster-unmatched":
					return []CapacityRefreshDemand{{ClusterID: "00000000-0000-4000-8000-000000000099", Namespace: cfg.NamespaceRef{Name: "synthetic-private-namespace", UID: "ns"}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "synthetic-private-workload", UID: "workload"}, NotAfter: time.Now().Add(time.Minute)}}, nil
				default:
					return nil, nil
				}
			})
			var stages []string
			runner.DemandReport = func(err error, elapsed, left time.Duration, stage string) {
				if err != cfg.ErrUnavailable || elapsed < 0 || left != 0 {
					t.Fatal("unexpected diagnostic cause/timing")
				}
				stages = append(stages, stage)
				cancel()
			}
			runner.runDemands(ctx, &capacityCurrentSource{})
			if reads != 1 {
				t.Fatal("diagnostic repeated read", reads)
			}
			if mode == "empty" {
				if len(stages) != 0 {
					t.Fatal("empty success became a failure", stages)
				}
				return
			}
			if len(stages) != 1 || stages[0] != mode {
				t.Fatal("missing closed demand boundary", mode, stages)
			}
		})
	}
}
