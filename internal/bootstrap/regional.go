package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	capacityapp "asservat.local/asservat/internal/application/capacity"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
)

// Regional is the outbound regional connector process (ADR-168/169). It owns
// its process keys and cluster credential and reaches the hub only through
// the federation endpoint; it holds no hub SQL, signing or audit credential.
type Regional struct {
	credentials *mtls.ConnectorProcessCredentials
	rotator     fleetapp.ClusterCredentialRotator
	bootstrap   regionalBootstrap
	context     *regionalContext  // nil without the optional ADR-171 input
	capacity    *regionalCapacity // nil without the optional ADR-197 input
	closers     []func()
	// API round trips of the shared observer and probe clients, for the
	// executor's stop line (ADR-196): counts and transport time only.
	observerStats, probeStats regionalAPIStats
}

// lifecycleTiming reports the first completed hub conversation of each
// purpose, its elapsed time and the observer client's calls during it
// (ADR-197 spike): the cost of answering a regional read through the
// lifecycle channel. Calls may include concurrent work on the same client.
func (r *Regional) lifecycleTiming() func(value.ConnectorLifecyclePurpose) func() {
	var seen sync.Map
	return func(purpose value.ConnectorLifecyclePurpose) func() {
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

// ponytail: fixed supervision cadences. Process leaves renew one minute early
// within thirty-minute periods; rotation is due daily.
const (
	regionalRetry     = 5 * time.Second
	regionalReconcile = time.Minute
	regionalRotation  = time.Minute
)

func RunRegional(ctx context.Context, podUID string) error {
	files, err := os.OpenRoot(contracts.RegionalDeploymentRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer files.Close()
	r, err := NewRegional(ctx, files, podUID)
	if err != nil {
		return err
	}
	defer r.Close()
	return r.Run(ctx)
}

func readRegionalDeployment(ctx context.Context, files *os.Root) (contracts.RegionalDeployment, error) {
	b, err := mounts.Read(ctx, files, "regional.json", contracts.RegionalDeploymentMaxBytes)
	if err != nil {
		return contracts.RegionalDeployment{}, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeRegionalDeployment(bytes.NewReader(b))
	if err != nil || c.Format != contracts.RegionalDeploymentFormat {
		return contracts.RegionalDeployment{}, mounts.ErrUnavailable
	}
	for _, id := range []string{c.InstallationID, c.ClusterID, c.PermissionRootID, c.IssuerEpoch, c.PeerID, c.Namespace.UID, c.Deployment.UID, c.Source.UID, c.ClusterCredential.UID} {
		if !authorization.UUID(id) {
			return contracts.RegionalDeployment{}, mounts.ErrUnavailable
		}
	}
	for _, name := range []string{c.Namespace.Name, c.Deployment.Name, c.Source.Name, c.ClusterCredential.Name, c.ClusterCredentialAccount, c.Hub.ServerName} {
		if !identity.Text(name, 253) {
			return contracts.RegionalDeployment{}, mounts.ErrUnavailable
		}
	}
	if !ownerEndpoint(c.Kubernetes.Endpoint) || !ownerEndpoint(c.Hub.Endpoint) || len(c.ConfigurationProbes) > 8 {
		return contracts.RegionalDeployment{}, mounts.ErrUnavailable
	}
	for _, g := range []contracts.OwnerDeploymentGuard{c.WorkloadGuard, c.SourceGuard} {
		if !identity.Text(g.Name, 253) || !authorization.UUID(g.PolicyUID) || !authorization.UUID(g.BindingUID) || !identity.Text(g.BindingResourceVersion, 128) || g.PolicyGeneration < 1 || len(g.Administrators) < 1 || len(g.Administrators) > 32 {
			return contracts.RegionalDeployment{}, mounts.ErrUnavailable
		}
	}
	if !validRegionalAPIContext(c) || !validRegionalCapacity(c) {
		return contracts.RegionalDeployment{}, mounts.ErrUnavailable
	}
	return c, nil
}

func regionalActors(in []contracts.OwnerDeploymentActor) []cfg.KubernetesActor {
	out := make([]cfg.KubernetesActor, len(in))
	for i, a := range in {
		out[i] = cfg.KubernetesActor{Kind: a.Kind, Name: a.Name}
	}
	return out
}

func regionalPin(g contracts.OwnerDeploymentGuard) kube.GuardPin {
	return kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}
}

type regionalPodToken struct{ inputs *providerInputs }

func (s regionalPodToken) ReadConnectorPodToken(ctx context.Context) ([]byte, error) {
	b, err := s.inputs.token("connector-pod.token")(ctx)
	if err != nil || !contracts.ValidWorkerToken(b) {
		clear(b)
		return nil, mounts.ErrUnavailable
	}
	return b, nil
}

// regionalLocal answers the hub's delegated reads in this cluster and logs a
// closed cause for each failed local read (operator diagnostics only).
type regionalLocal struct {
	native *kube.ConnectorLifecycleReader
	source *kube.ConnectorIdentitySource
}

func regionalLocalFailed(read string, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "connector local "+read+" failed: "+regionalCause(err))
	}
}

// regionalLocalTimed also names the failed step, the elapsed time and the
// deadline the hub's conversation left when the read began (ADR-197
// diagnostics); closed values only.
func regionalLocalTimed(read string, ctx context.Context, started time.Time, err error) {
	if err == nil {
		return
	}
	cause := regionalCause(err)
	var step interface{ FixedStep() string }
	if errors.As(err, &step) {
		cause = step.FixedStep() + " (" + cause + ")"
	}
	left := "none"
	if d, ok := ctx.Deadline(); ok {
		left = d.Sub(started).Round(10 * time.Millisecond).String()
	}
	fmt.Fprintf(os.Stderr, "connector local %s failed: %s after %s of %s\n", read, cause, time.Since(started).Round(10*time.Millisecond), left)
}

func (l regionalLocal) BeginConnectorLifecycle(ctx context.Context, r fleetapp.ConnectorLifecycleRequest) (fleetapp.ConnectorLifecycleOperation, error) {
	op, err := l.native.BeginConnectorLifecycle(ctx, r)
	regionalLocalFailed("begin", err)
	if err != nil {
		return nil, err
	}
	return regionalOperation{op}, nil
}

type regionalOperation struct {
	fleetapp.ConnectorLifecycleOperation
}

func (o regionalOperation) Read(ctx context.Context, phase value.ConnectorLifecyclePhase) (value.ConnectorLifecycleObservation, error) {
	out, err := o.ConnectorLifecycleOperation.Read(ctx, phase)
	regionalLocalFailed("phase", err)
	return out, err
}

func (l regionalLocal) ReadConnectorIdentitySource(ctx context.Context) (value.ConnectorIdentitySource, error) {
	started := time.Now()
	out, err := l.source.ReadConnectorIdentitySource(ctx)
	regionalLocalTimed("source", ctx, started, err)
	return out, err
}

func (l regionalLocal) ReadConnectorIdentityConfiguration(ctx context.Context) (fleetapp.ConnectorIdentityConfiguration, error) {
	started := time.Now()
	out, err := l.source.ReadConnectorIdentityConfiguration(ctx)
	regionalLocalTimed("configuration", ctx, started, err)
	return out, err
}

func NewRegional(ctx context.Context, files *os.Root, podUID string) (r *Regional, err error) {
	if ctx == nil || ctx.Err() != nil || files == nil || !authorization.UUID(podUID) || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	c, err := readRegionalDeployment(ctx, files)
	if err != nil {
		return nil, err
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
	in := &providerInputs{files: files, kubernetesEndpoint: c.Kubernetes}
	r.closers = append(r.closers, in.closeHTTP)
	control := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	observerConfig := in.kubernetes("kube-observer.token")
	observerConfig.Wrap(r.observerStats.wrap)
	observer, err := kube.NewPermissionClient(observerConfig, c.ClusterID, control, time.Now)
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	probeConfig := in.kubernetes("kube-probe.token")
	probeConfig.Wrap(r.probeStats.wrap)
	probe, err := kube.NewPermissionClient(probeConfig, c.ClusterID, control, time.Now)
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	probes := make([]cfg.OwnerConfigurationProbe, len(c.ConfigurationProbes))
	for i, p := range c.ConfigurationProbes {
		probes[i] = cfg.OwnerConfigurationProbe{ConfigMap: p.ConfigMap, ServiceAccount: p.ServiceAccount}
	}
	plan := cfg.OwnerWorkloadAdministration{Name: c.WorkloadGuard.Name, Deployment: c.Deployment.Name, DeploymentUID: c.Deployment.UID, ControlNamespace: control, Administrators: regionalActors(c.WorkloadGuard.Administrators), ConfigurationProbes: probes,
		CredentialSecrets: []cfg.OwnerCredentialSecret{{Secret: c.ClusterCredential.Name, ServiceAccount: c.ClusterCredentialAccount}}}
	if c.APIContext != nil {
		// The installed guard admits only the exact capacity/execution start writes.
		if plan.APIContextStarts, err = ownerDeploymentStarts(&c.APIContext.Starts); err != nil {
			return r, mounts.ErrUnavailable
		}
	}
	guard, err := kube.NewOwnerWorkloadProtection(observer, probe, plan, regionalPin(c.WorkloadGuard))
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	sourcePlan := cfg.ConfigMapAdministration{Name: c.SourceGuard.Name, SourceName: c.Source.Name, ControlNamespace: control, Administrators: regionalActors(c.SourceGuard.Administrators)}
	protection, err := kube.NewConnectorIdentityProtection(observer, probe, sourcePlan, regionalPin(c.SourceGuard))
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	binding := value.PeerBinding{InstallationID: c.InstallationID, ClusterID: c.ClusterID, IssuerEpoch: c.IssuerEpoch, PeerID: c.PeerID, Role: value.ConnectorPeer}
	source, err := kube.NewConnectorIdentitySource(observer, protection, c.Source.Name, c.Source.UID, c.PermissionRootID, binding)
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	// The process profile is this cluster's current protected source, including
	// the current guard's protection digest; the hub pins the same document.
	current, err := source.ReadConnectorIdentityConfiguration(startup)
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	native, err := kube.NewConnectorLifecycleReader(observer, source, guard, regionalPodToken{in})
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	secret, err := kube.NewClusterCredentialSecretForConfig(in.kubernetes("kube-observer.token"), c.Namespace.Name, c.ClusterCredential.Name, c.ClusterCredential.UID)
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	roots, _, err := mtls.OwnerTrustRoots(c.Hub.Roots, time.Now())
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	channel, err := connectorlifecycle.NewClient(c.Hub.Endpoint, c.Hub.ServerName, roots)
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	rotation, err := mtls.NewClusterCredentialClient(c.Hub.Endpoint, c.Hub.ServerName, roots)
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	r.rotator = fleetapp.ClusterCredentialRotator{Profile: value.ClusterCredentialProfile{RootID: c.PermissionRootID, PeerID: c.PeerID, InstallationID: c.InstallationID, ClusterID: c.ClusterID}, Policy: value.DefaultClusterCredentialPolicy(), Store: secret, Exchange: rotation, Now: time.Now}
	lifecycle := &RegionalLifecycle{Client: channel, Local: regionalLocal{native, source}, Credential: r.rotator, Now: time.Now, Timing: r.lifecycleTiming()}
	r.bootstrap = regionalBootstrap{store: secret, channel: channel, local: regionalLocal{native, source}, binding: binding, root: c.PermissionRootID, now: time.Now}
	r.credentials, err = mtls.NewConnectorProcessCredentials(ctx, current.Source.Observation.Profile, podUID, lifecycle, lifecycle, source, lifecycle, time.Now)
	if err != nil {
		return r, mounts.ErrUnavailable
	}
	r.closers = append(r.closers, r.credentials.Close)
	if c.APIContext != nil {
		var closers []func()
		r.context, closers, err = newRegionalContext(startup, c, in, podUID, observer, probe, source, guard, lifecycle, r.credentials)
		r.closers = append(r.closers, closers...)
		if err != nil {
			return r, mounts.ErrUnavailable
		}
	}
	if c.Capacity != nil {
		var closers []func()
		r.capacity, closers, err = newRegionalCapacity(startup, c, in, podUID, plan, sourcePlan, binding, lifecycle)
		r.closers = append(r.closers, closers...)
		if err != nil {
			return r, mounts.ErrUnavailable
		}
	}
	return r, nil
}

// Run supervises enrollment, renewal and cluster credential rotation until
// ctx ends. A fenced credential is permanent and stops the process; every
// other failure is retried as a new bounded conversation.
func (r *Regional) Run(ctx context.Context) error {
	if r == nil || r.credentials == nil || ctx == nil {
		return mounts.ErrUnavailable
	}
	enrolled, bootstrapped, last := false, false, ""
	wait := time.NewTimer(0)
	defer wait.Stop()
	rotate := time.NewTicker(regionalRotation)
	defer rotate.Stop()
	// Context start runs only while credentials are active; a stopped run is
	// retried after the fixed delay, never resumed with old exchanges.
	contextDone := make(chan error, 1)
	contextRunning, contextLast := false, ""
	var contextRetry <-chan time.Time
	contextCtx, stopContext := context.WithCancel(ctx)
	// ADR-197: the capacity standby runs beside context start, with its own
	// fixed retry, while credentials are active.
	capacityDone := make(chan error, 1)
	capacityRunning, capacityLast := false, ""
	var capacityRetry <-chan time.Time
	defer func() {
		stopContext()
		if contextRunning {
			<-contextDone
		}
		if capacityRunning {
			<-capacityDone
		}
	}()
	var attemptAt time.Time
	var observerAt, probeAt int64
	var observerTime, probeTime time.Duration
	startContext := func() {
		if r.context == nil || contextRunning || !enrolled || contextRetry != nil {
			return
		}
		attemptAt = time.Now()
		observerAt, observerTime = r.observerStats.load()
		probeAt, probeTime = r.probeStats.load()
		contextRunning = true
		go func() { contextDone <- r.context.run(contextCtx, r.credentials) }()
	}
	startCapacity := func() {
		if r.capacity == nil || r.context == nil || capacityRunning || !enrolled || capacityRetry != nil {
			return
		}
		capacityRunning = true
		go func() { capacityDone <- r.capacity.run(contextCtx, r.credentials, r.context.settings) }()
	}
	for {
		startContext()
		startCapacity()
		select {
		case <-ctx.Done():
			return nil
		case err := <-capacityDone:
			capacityRunning = false
			cause := regionalCause(err)
			var step interface{ FixedStep() string }
			if errors.As(err, &step) {
				cause = step.FixedStep() + " (" + cause + ")"
			}
			if err != nil && cause != capacityLast {
				fmt.Fprintln(os.Stderr, "regional capacity stopped: "+cause)
				capacityLast = cause
			}
			capacityRetry = time.After(regionalRetry)
		case <-capacityRetry:
			capacityRetry = nil
		case err := <-contextDone:
			contextRunning = false
			cause := regionalCause(err)
			var step interface{ FixedStep() string }
			if errors.As(err, &step) {
				cause = step.FixedStep() + " (" + cause + ")"
			}
			if cause != contextLast {
				oc, ot := r.observerStats.load()
				pc, pt := r.probeStats.load()
				fmt.Fprintf(os.Stderr, "regional context start stopped: %s; attempt %s, observer %d calls %s, probe %d calls %s\n", cause,
					time.Since(attemptAt).Round(10*time.Millisecond), oc-observerAt, (ot - observerTime).Round(10*time.Millisecond), pc-probeAt, (pt - probeTime).Round(10*time.Millisecond))
				contextLast = cause
			}
			contextRetry = time.After(regionalRetry)
		case <-contextRetry:
			contextRetry = nil
		case <-wait.C:
			// ADR-193: a generation-0 Secret enrolls generation 1 first.
			if !bootstrapped {
				err := r.bootstrap.Reconcile(ctx)
				if errors.Is(err, value.ErrClusterCredentialFenced) {
					return err
				}
				if err != nil {
					if cause := regionalCause(err); cause != last {
						fmt.Fprintln(os.Stderr, "connector bootstrap pending: "+cause)
						last = cause
					}
					wait.Reset(regionalRetry)
					continue
				}
				bootstrapped = true
			}
			err := r.credentials.Reconcile(ctx)
			if err == nil && !enrolled {
				enrolled = true
				fmt.Fprintln(os.Stderr, "connector process credentials active")
			}
			// One closed cause per change, never inputs or remote text.
			if cause := regionalCause(err); err != nil && cause != last {
				fmt.Fprintln(os.Stderr, "connector enrollment pending: "+cause)
				last = cause
			} else if err == nil {
				last = ""
			}
			if enrolled {
				wait.Reset(regionalReconcile)
			} else {
				wait.Reset(regionalRetry)
			}
		case <-rotate.C:
			if err := r.rotator.Reconcile(ctx); errors.Is(err, value.ErrClusterCredentialFenced) {
				return err
			}
		}
	}
}

func regionalCause(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, value.ErrClusterCredentialFenced):
		return "cluster-credential-fenced"
	case errors.Is(err, errRegionalCredentialWrite):
		return "cluster-credential-write"
	case errors.Is(err, errRegionalBootstrapExpired):
		return "cluster-bootstrap-expired"
	case errors.Is(err, errRegionalCredential):
		return "cluster-credential"
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
