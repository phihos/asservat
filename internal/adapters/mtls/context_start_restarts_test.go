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

func (f *restartRegion) ObserveWorkloadRestarts(_ context.Context, r targets.RestartRequest) (targets.RestartObservation, error) {
	f.calls++
	if r.Alert && r.AlertLabels["severity"] != "critical" {
		// ADR-231: a region without an Alertmanager.
		return targets.RestartObservation{}, targets.ErrUnsupported
	}
	w := f.work.Target
	now := time.Now().UTC().Truncate(time.Microsecond)
	o := targets.RestartObservation{ClusterID: r.ClusterID, Namespace: configuration.NamespaceRef{Name: r.Namespace, UID: w.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: r.Kind, Name: r.Name, UID: w.WorkloadUID}, Pods: []targets.PodRestarts{}, Probe: r.Probe, Alert: r.Alert, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	for n := range f.pods {
		name := fmt.Sprintf("app-%d", n)
		if f.long {
			name += "-" + strings.Repeat("x", 240)
		}
		pod := targets.PodRestarts{Name: name, UID: fmt.Sprintf("00000000-0000-4000-8000-%012d", n), Restarts: int64(n), Reason: "Error", ExitCode: 137}
		if r.Probe != "" || r.Alert {
			// ADR-230: a Deployment Pod name of the maximal 63 characters and
			// four-digit failure counts.
			pod.Name = (name + "-" + strings.Repeat("p", 63))[:63]
			pod.ProbeFailures, pod.ProbeLast = 1000, 1792000000+int64(n)
		}
		o.Pods = append(o.Pods, pod)
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
	request := targets.RestartRequest{WorkloadRequest: targets.WorkloadRequest{ClusterID: work.Target.ClusterID, Namespace: "app", Kind: "Deployment", Name: "app"}}
	o, err := hub.ObserveWorkloadRestarts(ctx, request)
	if err != nil || len(o.Pods) != targets.MaxRestartPods || o.Workload.UID != work.Target.WorkloadUID || o.FreshUntil.After(exchange.Receiver().ValidUntil.Add(time.Second)) {
		t.Fatal("restart observation", err, len(o.Pods))
	}
	// A probe observation of 128 Pods still fits one answer frame.
	probe := request
	probe.Probe, probe.ProbeWindowSeconds = "Readiness", 60
	if o, err = hub.ObserveWorkloadRestarts(ctx, probe); err != nil || len(o.Pods) != targets.MaxRestartPods || o.Probe != "Readiness" || o.Pods[1].ProbeFailures != 1000 {
		t.Fatal("probe observation", err, len(o.Pods))
	}
	// ADR-231: an alert observation carries its label matchers to the region
	// and its level data back; a region without an Alertmanager answers
	// unsupported, which activation reports as such.
	alert := request
	alert.Alert, alert.AlertLabels = true, map[string]string{"severity": "critical", "alertname": strings.Repeat("a", 256)}
	if o, err = hub.ObserveWorkloadRestarts(ctx, alert); err != nil || len(o.Pods) != targets.MaxRestartPods || !o.Alert || o.Probe != "" || o.Pods[1].ProbeFailures != 1000 {
		t.Fatal("alert observation", err, len(o.Pods))
	}
	alert.AlertLabels = map[string]string{"severity": "warning"}
	if _, err = hub.ObserveWorkloadRestarts(ctx, alert); !errors.Is(err, targets.ErrUnsupported) {
		t.Fatal("unsupported alert observation", err)
	}
	region.long = true
	if _, err = hub.ObserveWorkloadRestarts(ctx, request); !errors.Is(err, targets.ErrUnavailable) {
		t.Fatal("oversized answer was not a closed failure", err)
	}
	if _, err = hub.ResolveWorkload(ctx, request.WorkloadRequest); err != nil {
		t.Fatal("standby lost after a closed restart failure", err)
	}
	if region.calls != 5 {
		t.Fatal("region observed", region.calls)
	}
}
