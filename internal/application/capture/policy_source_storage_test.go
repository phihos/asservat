package capture

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/targets"
)

type sourceStorageFake struct {
	fresh   time.Time
	err     error
	demands []targets.Request
}

func (f *sourceStorageFake) ContextStorage(context.Context, authorization.Target) (ContextStorageObservation, error) {
	return ContextStorageObservation{Binding: value.StorageBinding{FreshUntil: f.fresh}}, f.err
}

func (f *sourceStorageFake) DemandCapacityRefresh(_ context.Context, r targets.Request) error {
	f.demands = append(f.demands, r)
	return nil
}

func TestSourceMaintenanceDemandsExpiringStorageBinding(t *testing.T) {
	now := time.Unix(1000, 0)
	o := targets.RestartObservation{ClusterID: "c", Namespace: cfg.NamespaceRef{Name: "ns", UID: "nu"}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "w", UID: "wu"}, Pods: []targets.PodRestarts{{Name: "p", UID: "pu"}}}
	for name, tc := range map[string]struct {
		fresh  time.Time
		err    error
		demand bool
	}{
		"fresh":    {now.Add(25 * time.Second), nil, false},
		"expiring": {now.Add(10 * time.Second), nil, true},
		"missing":  {time.Time{}, value.ErrUnavailable, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := &sourceStorageFake{fresh: tc.fresh, err: tc.err}
			s := &PolicySourceRuntime{Storage: f, Refresh: f, Now: func() time.Time { return now }}
			s.demandStorage(t.Context(), o)
			if (len(f.demands) == 1) != tc.demand || tc.demand && (f.demands[0].Workload.UID != "wu" || f.demands[0].PodUID != "pu") {
				t.Fatal("demand", f.demands)
			}
		})
	}
}
