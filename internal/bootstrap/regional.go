package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"k8s.io/client-go/rest"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	capacityapp "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
)

// Regional is the outbound regional connector process (ADR-169). It
// authenticates to the hub with its ServiceAccount token (ADR-334) and holds
// no hub SQL, signing or audit credential.
type Regional struct {
	context *regionalContext // nil without the optional ADR-171 input
	nodes   *regionalNodes   // nil without the optional ADR-246 input
	// bindings delivers this cluster's AccessBindings to the hub (ADR-329);
	// nil in mode=combined, where the hub-worker observes the hub cluster.
	bindings    AccessBindingReader
	lifecycle   *RegionalLifecycle
	watchConfig *rest.Config
	closers     []func()
	// API round trips of the shared observer client, for the executor's stop
	// line (ADR-196): counts and transport time only.
	observerStats regionalAPIStats
}

// lifecycleTiming reports the first completed hub conversation of each
// purpose, its elapsed time and the observer client's calls during it
// (ADR-197 spike): the cost of answering a regional read through the
// lifecycle channel. Calls may include concurrent work on the same client.
func (r *Regional) lifecycleTiming() func(connectorlifecycle.Purpose) func() {
	var seen sync.Map
	return func(purpose connectorlifecycle.Purpose) func() {
		started := time.Now()
		before, _ := r.observerStats.load()
		return func() {
			if _, loaded := seen.LoadOrStore(purpose, true); loaded {
				return
			}
			after, _ := r.observerStats.load()
			fmt.Fprintf(os.Stderr, "connector lifecycle %s took %s, observer %d calls\n", purpose, time.Since(started).Round(10*time.Millisecond), after-before)
		}
	}
}

type regionalAPIStats struct{ calls, nanos atomic.Int64 }

func (s *regionalAPIStats) wrap(t http.RoundTripper) http.RoundTripper {
	return regionalCountingTransport{t, s}
}
func (s *regionalAPIStats) load() (int64, time.Duration) {
	return s.calls.Load(), time.Duration(s.nanos.Load())
}

type regionalCountingTransport struct {
	next  http.RoundTripper
	stats *regionalAPIStats
}

func (t regionalCountingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.next.RoundTrip(r)
	t.stats.calls.Add(1)
	t.stats.nanos.Add(int64(time.Since(start)))
	return resp, err
}

// regionalRetry is the fixed delay before a stopped context start reopens.
const regionalRetry = 5 * time.Second

func RunRegional(ctx context.Context, podUID string) error {
	// The test diagnostics keep connector lines prefixed "regional".
	logOpeningStats(ctx, "regional kube opening")
	files, err := os.OpenRoot(contracts.ConnectorConfigRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer files.Close()
	// Combined mode: the hub-api writes the offer after it starts, so the
	// connector waits in-process instead of exiting into kubelet back-off.
	var r *Regional
	if err = waitStartup(ctx, "connector", startupLog, func(ctx context.Context) (err error) {
		r, err = NewRegional(ctx, files, podUID)
		return err
	}, nil); err != nil {
		return err
	}
	defer r.Close()
	return r.Run(ctx)
}

func regionalLocalFailed(read string, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "connector local "+read+" failed: "+regionalCause(err))
	}
}

func NewRegional(ctx context.Context, files *os.Root, podUID string) (r *Regional, err error) {
	if ctx == nil || ctx.Err() != nil || files == nil || !authorization.UUID(podUID) || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	r = &Regional{}
	defer func() {
		if err != nil {
			r.Close()
			r = nil
		}
	}()
	startup, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	in := &providerInputs{files: files}
	r.closers = append(r.closers, in.closeHTTP)
	raw, err := readConnectorConfig(startup, in)
	if err != nil {
		return r, err
	}
	apiRoots, err := kubernetesRoots(startup, in)
	if err != nil {
		return r, err
	}
	in.kubernetesEndpoint = contracts.OwnerProviderEndpoint{Endpoint: "https://kubernetes.default.svc", Roots: apiRoots}
	// Combined mode: the hub's own cluster and local connector peer come
	// from the IDs Secret (field map class S), not from values.
	var ids contracts.InstallationIDs
	if raw.Mode == contracts.ConnectorModeCombined {
		if ids, err = readCombinedIDs(); err != nil {
			return r, err
		}
		raw.ClusterID, raw.PeerID = ids.ClusterID, ids.PeerID
	}
	c, err := resolveRegionalConfig(startup, in, raw)
	if err != nil {
		return r, err
	}
	if raw.Mode == contracts.ConnectorModeCombined && !combinedOfferMatches(c.offer, ids) {
		return r, &fixedStepError{"offer-ids", mounts.ErrUnavailable}
	}
	// N values: the connector's own namespace, account and Deployment UIDs,
	// read by name once.
	workload, err := kube.ReadConnectorWorkload(startup, in.kubernetes(contracts.ConnectorKubeTokenFile), c.ClusterID, c.Namespace, c.ServiceAccount, c.Deployment)
	if err != nil {
		return r, &fixedStepError{"workload", err}
	}
	control := cfg.NamespaceRef{Name: c.Namespace, UID: workload.NamespaceUID}
	observerConfig := kube.WithOpeningBurst(in.kubernetes(contracts.ConnectorKubeTokenFile))
	observerConfig.Wrap(r.observerStats.wrap)
	observer, err := kube.NewPermissionClient(observerConfig, c.ClusterID, control, time.Now)
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	roots, _, err := mtls.OwnerTrustRoots(c.hub.Roots, time.Now())
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	hubToken := func() ([]byte, error) { return in.read(context.Background(), contracts.ConnectorHubTokenFile, 16<<10) }
	channel, err := connectorlifecycle.NewClient(c.hub.Endpoint, c.hub.ServerName, roots, hubToken)
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	process := value.ConnectorProcessIdentity{Binding: c.binding, PodUID: podUID, ProcessEpoch: uuid.NewString()}
	lifecycle := &RegionalLifecycle{Client: channel, Process: process, RootID: c.rootID(), Now: time.Now, Timing: r.lifecycleTiming()}
	if raw.Mode == contracts.ConnectorModeCluster {
		r.bindings, r.lifecycle, r.watchConfig = observer, lifecycle, in.kubernetes(contracts.ConnectorKubeTokenFile)
	}
	if c.executor {
		var closers []func()
		r.context, closers, err = newRegionalContext(startup, c, in, podUID, workload, lifecycle, hubToken)
		r.closers = append(r.closers, closers...)
		if err != nil {
			return r, err
		}
	}
	if c.Collector != nil {
		if r.nodes, err = newRegionalNodes(startup, c, in); err != nil {
			return r, err
		}
		r.closers = append(r.closers, r.nodes.close)
		// ADR-248: manual packet recordings need both the node channel and
		// the context start's output and Pod reads.
		if r.context != nil {
			recordings := r.context.output.recordings
			if recordings == nil {
				recordings = NewConnectorRecordings(r.nodes.server.Channel, r.context.collector, time.Now, func(line string) { fmt.Fprintln(os.Stderr, line) })
			} else {
				recordings.nodes = r.nodes.server.Channel
			}
			r.nodes.server.Channel.SetPacketSink(recordings)
			r.nodes.server.Channel.SetProfileSink(recordings)
			recordings.profileEndpoints = r.context.targets
			authorization, authErr := newRegionalProfileAuthorizationReader(startup, in, c)
			if authErr != nil {
				return r, mounts.ErrUnavailable
			}
			if authorization != nil {
				recordings.SetProfileAuthorizationReader(authorization)
				r.closers = append(r.closers, authorization.close)
			}
			recordings.SetPeers(r.context.peers)
			r.context.output.recordings = recordings
		}
	}
	return r, nil
}

// Run serves context starts and deliveries until ctx ends; a stopped
// context start reopens after a fixed delay, never resuming old exchanges.
func (r *Regional) Run(ctx context.Context) error {
	if r == nil || ctx == nil {
		return mounts.ErrUnavailable
	}
	contextDone := make(chan error, 1)
	contextRunning, contextLast := false, ""
	var contextRetry <-chan time.Time
	contextCtx, stopContext := context.WithCancel(ctx)
	defer func() {
		stopContext()
		if contextRunning {
			<-contextDone
		}
	}()
	// ADR-246: the node listener runs for the process lifetime; its failure
	// stops the connector like any other fixed input failure.
	nodesDone := make(chan error, 1)
	if r.nodes != nil {
		go func() { nodesDone <- r.nodes.serve(contextCtx) }()
	}
	defer func() {
		if r.nodes != nil {
			stopContext()
			<-nodesDone
			r.nodes = nil
		}
	}()
	// ADR-329/330: watch-driven deliveries beside the context starts.
	if r.bindings != nil {
		ready := make(chan struct{})
		close(ready)
		wait := goJoined(func() { r.runDeliveries(contextCtx, ready) })
		defer func() { stopContext(); wait() }()
	}
	var attemptAt time.Time
	var observerAt int64
	var observerTime time.Duration
	startContext := func() {
		if r.context == nil || contextRunning || contextRetry != nil {
			return
		}
		attemptAt = time.Now()
		observerAt, observerTime = r.observerStats.load()
		contextRunning = true
		go func() { contextDone <- r.context.run(contextCtx) }()
	}
	for {
		startContext()
		select {
		case <-ctx.Done():
			return nil
		case err := <-nodesDone:
			r.nodes = nil
			fmt.Fprintln(os.Stderr, "connector node listener stopped: "+regionalCause(err))
			return mounts.ErrUnavailable
		case err := <-contextDone:
			contextRunning = false
			cause := regionalCause(err)
			var step interface{ FixedStep() string }
			if errors.As(err, &step) {
				cause = step.FixedStep() + " (" + cause + ")"
			}
			if cause != contextLast {
				oc, ot := r.observerStats.load()
				fmt.Fprintf(os.Stderr, "regional context start stopped: %s; attempt %s, observer %d calls %s\n", cause,
					time.Since(attemptAt).Round(10*time.Millisecond), oc-observerAt, (ot - observerTime).Round(10*time.Millisecond))
				contextLast = cause
			}
			contextRetry = time.After(regionalRetry)
		case <-contextRetry:
			contextRetry = nil
		}
	}
}

func regionalCause(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errRegionalChannel):
		return "hub-channel"
	case errors.Is(err, errRegionalRefused):
		return "hub-refused"
	case errors.Is(err, capacityapp.ErrCapacityNotAllocated):
		return "not-allocated"
	case errors.Is(err, capacityapp.ErrBudgetFull):
		return "budget-full"
	case errors.Is(err, capacityapp.ErrBudgetInvalid):
		return "budget-invalid"
	case errors.Is(err, cfg.ErrChanged):
		return "changed"
	case errors.Is(err, value.ErrDenied):
		return "denied"
	case errors.Is(err, value.ErrInvalid):
		return "invalid"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "cancelled"
	}
	return "unavailable"
}

func (r *Regional) Close() {
	if r == nil {
		return
	}
	for i := len(r.closers) - 1; i >= 0; i-- {
		r.closers[i]()
	}
	r.closers = nil
}
