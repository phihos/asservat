package mtls

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/contextstart"
)

// restartRegion adds the ADR-228 restart observation to the synthetic region.
type restartRegion struct {
	*regionalOperationsFixture
	pods  int
	long  bool
	calls int
}

func (f *restartRegion) ObserveWorkloadRestarts(_ context.Context, r targets.WorkloadRequest) (targets.RestartObservation, error) {
	f.calls++
	w := f.work.Target
	now := time.Now().UTC().Truncate(time.Microsecond)
	o := targets.RestartObservation{ClusterID: r.ClusterID, Namespace: configuration.NamespaceRef{Name: r.Namespace, UID: w.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: r.Kind, Name: r.Name, UID: w.WorkloadUID}, Pods: []targets.PodRestarts{}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	for n := range f.pods {
		name := fmt.Sprintf("app-%d", n)
		if f.long {
			name += "-" + strings.Repeat("x", 240)
		}
		o.Pods = append(o.Pods, targets.PodRestarts{Name: name, UID: fmt.Sprintf("00000000-0000-4000-8000-%012d", n), Restarts: int64(n), Reason: "Error", ExitCode: 137})
	}
	return o, nil
}

// The restart observation is one more pre-work query over actual TLS: it
// keeps the standby, and an answer too large for one frame is a closed
// failure rather than a truncated answer or a broken exchange.
func TestContextStartActualHTTP2RestartObservationQuery(t *testing.T) {
	f := newContextStartTLSFixture(t)
	region := &restartRegion{regionalOperationsFixture: &regionalOperationsFixture{t: t, process: f.api}, pods: targets.MaxRestartPods}
	f.targets = region
	exchange, stream := f.open(t)
	work, signer, _, _ := f.work(t, exchange.Receiver())
	region.work = work
	local := contextstart.RegionalLocal{Process: region, Targets: region, Local: region, Starts: region, Output: region, Collector: region, Source: f.connector, Now: time.Now}
	go func() {
		defer stream.Close()
		_ = contextstart.ServeRegionalOperations(exchange.Context(), stream, exchange.Receiver(), signer, local, time.Now)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	hub := contextstart.Targets{Router: f.router, Now: time.Now}
	request := targets.WorkloadRequest{ClusterID: work.Target.ClusterID, Namespace: "app", Kind: "Deployment", Name: "app"}
	o, err := hub.ObserveWorkloadRestarts(ctx, request)
	if err != nil || len(o.Pods) != targets.MaxRestartPods || o.Workload.UID != work.Target.WorkloadUID || o.FreshUntil.After(exchange.Receiver().ValidUntil.Add(time.Second)) {
		t.Fatal("restart observation", err, len(o.Pods))
	}
	region.long = true
	if _, err = hub.ObserveWorkloadRestarts(ctx, request); !errors.Is(err, targets.ErrUnavailable) {
		t.Fatal("oversized answer was not a closed failure", err)
	}
	if _, err = hub.ResolveWorkload(ctx, request); err != nil {
		t.Fatal("standby lost after a closed restart failure", err)
	}
	if region.calls != 2 {
		t.Fatal("region observed", region.calls)
	}
}
