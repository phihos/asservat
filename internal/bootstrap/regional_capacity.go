package bootstrap

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
)

// regionalCapacity serves the hub-worker's ADR-197 v2 capacity observation:
// regionalStandbys outbound standbys to the hub owner's operation port, each
// answering at most one combined observation. Its Kubernetes clients are its
// own instances at the same fixed limits, so it never spends the executor's
// proof budget (ADR-199).
type regionalCapacity struct {
	c         contracts.RegionalCapacity
	owner     value.OwnerObservationPin
	roots     *x509.CertPool
	observer  *kube.PermissionClient
	source    *kube.ConnectorIdentitySource
	guard     *kube.OwnerWorkloadProtection
	metadata  *kube.ClusterObservationMetadata
	tokens    regionalPodToken
	lifecycle *RegionalLifecycle
	timed     *regionalCapacityTimed
}

func validRegionalCapacity(c contracts.RegionalDeployment) bool {
	k := c.Capacity
	if k == nil {
		return true
	}
	g, o := k.NamespaceGuard, k.Owner
	digest := func(s string) bool { _, ok := publicDigest(s); return ok }
	if c.APIContext == nil || !ownerDialAddress(k.OperationAddress) || !authorization.UUID(o.SourceUID) || !digest(o.TemplateDigest) || !digest(o.ImageDigest) || !digest(o.ProtectionDigest) ||
		!identity.Text(g.Name, 253) || !authorization.UUID(g.PolicyUID) || !authorization.UUID(g.BindingUID) || !identity.Text(g.BindingResourceVersion, 128) || g.PolicyGeneration < 1 || len(g.Administrators) < 1 || len(g.Administrators) > 32 ||
		!identity.Text(k.ProbeNamespace.Name, 63) || !authorization.UUID(k.ProbeNamespace.UID) || !identity.Text(k.ProbeAccount.Name, 253) || !authorization.UUID(k.ProbeAccount.UID) || !identity.Text(k.ProbeAudience, 512) ||
		len(k.Keys) < 1 || len(k.Keys) > 256 || !slices.IsSorted(k.Keys) || len(slices.Compact(slices.Clone(k.Keys))) != len(k.Keys) {
		return false
	}
	for _, key := range k.Keys {
		if !identity.Text(key, 253) {
			return false
		}
	}
	return true
}

// newRegionalCapacity builds the standby's inputs: its own observer and probe
// clients with fresh guards over the same pinned plans, the selector guard
// with the probe account's in-memory Pod-bound tokens, and the owner pin.
func newRegionalCapacity(ctx context.Context, c contracts.RegionalDeployment, in *providerInputs, podUID string, workload cfg.OwnerWorkloadAdministration, sourcePlan cfg.ConfigMapAdministration, binding value.PeerBinding, lifecycle *RegionalLifecycle) (*regionalCapacity, []func(), error) {
	var closers []func()
	k := *c.Capacity
	control := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	out := &regionalCapacity{c: k, tokens: regionalPodToken{in}, lifecycle: lifecycle, timed: &regionalCapacityTimed{stats: &regionalAPIStats{}}}
	var err error
	observerConfig := in.kubernetes("kube-observer.token")
	observerConfig.Wrap(out.timed.stats.wrap)
	if out.observer, err = kube.NewPermissionClient(observerConfig, c.ClusterID, control, time.Now); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	probe, err := kube.NewPermissionClient(in.kubernetes("kube-probe.token"), c.ClusterID, control, time.Now)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	if out.guard, err = kube.NewOwnerWorkloadProtection(out.observer, probe, workload, regionalPin(c.WorkloadGuard)); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	protection, err := kube.NewConnectorIdentityProtection(out.observer, probe, sourcePlan, regionalPin(c.SourceGuard))
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	if out.source, err = kube.NewConnectorIdentitySource(out.observer, protection, c.Source.Name, c.Source.UID, c.PermissionRootID, binding); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	probeNS := cfg.NamespaceRef{Name: k.ProbeNamespace.Name, UID: k.ProbeNamespace.UID}
	// The capacity metadata (selector guard proof, workload reads, probe
	// tokens) gets its own observer instance at the same fixed limit. Sharing
	// the native reader's limiter let a guarded read's 14 calls starve the
	// final native bracket (ADR-197 CI continuation run 10).
	metadataConfig := in.kubernetes("kube-observer.token")
	metadataConfig.Wrap(out.timed.stats.wrap)
	read, err := kube.NewPermissionClient(metadataConfig, c.ClusterID, probeNS, time.Now)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	tokens, err := kube.NewCapacityTokens(ctx, read, k.ProbeAccount.Name, k.ProbeAudience, podUID)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	closers = append(closers, tokens.Close)
	selectorProbe, err := kube.NewPermissionClient(in.kubernetesToken(tokens.Token), c.ClusterID, probeNS, time.Now)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	_, name := kube.RegionalCapacityNames(c.Namespace.Name)
	if name != k.NamespaceGuard.Name {
		return nil, closers, mounts.ErrUnavailable
	}
	selector, err := kube.NewCapacityNamespaceGuard(read, selectorProbe, cfg.CapacityNamespaceAdministration{Name: name, Administrators: regionalActors(k.NamespaceGuard.Administrators), Keys: k.Keys,
		ProbeNamespace: probeNS, ProbeAccount: cfg.NamespaceRef{Name: k.ProbeAccount.Name, UID: k.ProbeAccount.UID}}, regionalPin(k.NamespaceGuard))
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	if out.metadata, err = kube.NewClusterObservationMetadata(read, selector, c.PermissionRootID); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	pool, err := regionalOwnerPool(c, c.APIContext.Owners.Configuration)
	if err != nil || pool.OperationPort == 0 {
		return nil, closers, mounts.ErrUnavailable
	}
	if out.roots, _, err = mtls.OwnerTrustRoots(c.APIContext.Owners.Configuration.IssuerRoots, time.Now()); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	template, _ := publicDigest(k.Owner.TemplateDigest)
	image, _ := publicDigest(k.Owner.ImageDigest)
	guard, _ := publicDigest(k.Owner.ProtectionDigest)
	out.owner = value.OwnerObservationPin{RootID: c.PermissionRootID, SourceUID: k.Owner.SourceUID, Pool: pool, TemplateDigest: template, ImageDigest: image, ProtectionDigest: guard}
	if !out.owner.Valid() {
		return nil, closers, mounts.ErrUnavailable
	}
	return out, closers, nil
}

// run composes the v2 client for the active process credentials and keeps
// one standby open until ctx ends or a component fails. The connector pin is
// the guarded executor settings' own Deployment pin.
func (r *regionalCapacity) run(ctx context.Context, credentials *mtls.ConnectorProcessCredentials, settings *kube.ConnectorAPISettingsProtection) error {
	installed, _, _, err := settings.ReadSettings(ctx)
	if err != nil {
		return &fixedStepError{"capacity-settings", err}
	}
	current, err := r.source.ReadConnectorIdentityConfiguration(ctx)
	if err != nil {
		return &fixedStepError{"capacity-source", err}
	}
	template, a := publicDigest(installed.TemplateDigest)
	image, b := publicDigest(installed.ImageDigest)
	protection, d := publicDigest(installed.WorkloadProtectionDigest)
	pin := value.ConnectorObservationPin{Profile: current.Source.Observation.Profile.Clone(), Roles: current.Source.Roles, TemplateDigest: template, ImageDigest: image, ProtectionDigest: protection}
	if !a || !b || !d || !pin.Valid() {
		return &fixedStepError{"capacity-pin", value.ErrUnavailable}
	}
	reader, err := kube.NewConnectorObservationOperationReader(r.observer, r.source, r.guard, r.tokens, pin)
	if err != nil {
		return &fixedStepError{"capacity-reader", err}
	}
	producer, err := mtls.NewConnectorObservationOperationProducer(pin, credentials, regionalTimedNative{reader, r.timed}, time.Now)
	if err != nil {
		return &fixedStepError{"capacity-producer", err}
	}
	client, err := mtls.NewConnectorObservationOperationClient(ctx, r.owner, r.c.OperationAddress, r.roots, producer, r.lifecycle, r.lifecycle, regionalTimedMetadata{r.metadata, r.timed}, regionalStandbys, time.Now)
	if err != nil {
		return &fixedStepError{"capacity-client", err}
	}
	defer client.Close()
	fmt.Fprintln(os.Stderr, "regional capacity standby active")
	var loops sync.WaitGroup
	for range regionalStandbys {
		loops.Add(1)
		go func() {
			defer loops.Done()
			r.standbys(ctx, client)
		}()
	}
	loops.Wait()
	return nil
}

// regionalStandbys keeps a second standby open: replacing a served one (local
// checks, TLS, Hello, hub authentication) takes longer than the hub-worker's
// pace, so with one standby every second request found none (ADR-197 CI
// continuation 2). The hub holder admits one more entry for cleanup lag.
const regionalStandbys = 2

// standbys keeps one of the standbys open until ctx ends.
func (r *regionalCapacity) standbys(ctx context.Context, client *mtls.ConnectorObservationOperationClient) {
	last, quick := "", 0
	for ctx.Err() == nil {
		// A standby that served or held its full interval is replaced at
		// once; a failed one at most once per second, so a refusing hub is
		// never hammered. The previous connection releases the client's one
		// standby slot asynchronously, so up to five failed opens right after a
		// served standby retry after 100 ms each instead. One closed stage and
		// cause is logged per change, never remote text.
		started := time.Now()
		opened, err := r.standby(ctx, client)
		if opened {
			quick = 5 // up to five quick retries after a served standby
		}
		turnover := !opened && quick > 0
		if turnover {
			quick--
		}
		stage := "open"
		if opened {
			stage = "serve"
		}
		cause := stage + " (" + regionalCause(err) + ")"
		var step interface{ FixedStep() string }
		if errors.As(err, &step) {
			cause = stage + "/" + regionalOutcome(err)
		}
		// A served standby's failure is logged every time with its elapsed
		// time, so window exhaustion is visible; open failures per change.
		if err != nil && (opened || cause != last) {
			if opened {
				cause += " after " + time.Since(started).Round(10*time.Millisecond).String()
			}
			fmt.Fprintln(os.Stderr, "regional capacity standby: "+cause)
			last = cause
		}
		pause := time.Until(started.Add(time.Second))
		if turnover {
			pause = 100 * time.Millisecond
		}
		if err != nil && pause > 0 && waitWorker(ctx, pause) != nil {
			return
		}
	}
}

func (r *regionalCapacity) standby(ctx context.Context, client *mtls.ConnectorObservationOperationClient) (bool, error) {
	root, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stream, err := client.Open(root, ownerRandomID())
	if err != nil {
		return false, err
	}
	defer stream.Close()
	return true, wire.ServeRegionalObservationOperation(stream.Context(), stream, time.Now)
}

// regionalCapacityTimed wraps the standby's native reader and metadata
// observer with closed per-change failure lines: the step, the elapsed time
// and the capacity client's API calls during it (ADR-197 diagnostics).
type regionalCapacityTimed struct {
	stats *regionalAPIStats
	mu    sync.Mutex
	last  string
}

func (t *regionalCapacityTimed) report(step string, started time.Time, calls int64, err error) {
	outcome := "ok"
	if err != nil {
		outcome = regionalCause(err)
		var inner interface{ FixedStep() string }
		if errors.As(err, &inner) {
			outcome = inner.FixedStep() + " (" + outcome + ")"
		}
	}
	after, _ := t.stats.load()
	t.mu.Lock()
	defer t.mu.Unlock()
	if line := step + ": " + outcome; line != t.last {
		t.last = line
		fmt.Fprintf(os.Stderr, "regional capacity %s after %s, %d calls\n", line, time.Since(started).Round(10*time.Millisecond), after-calls)
	}
}

type regionalTimedNative struct {
	inner fleetapp.ConnectorNativeObservationOperations
	t     *regionalCapacityTimed
}

func (n regionalTimedNative) OpenConnectorObservationOperation(ctx context.Context, r value.OwnerObservationRequest, p value.ConnectorProcessIdentity) (fleetapp.ConnectorNativeObservationOperation, error) {
	started := time.Now()
	calls, _ := n.t.stats.load()
	op, err := n.inner.OpenConnectorObservationOperation(ctx, r, p)
	n.t.report("native open", started, calls, err)
	if err != nil {
		return nil, err
	}
	return regionalTimedOperation{op, n.t}, nil
}

type regionalTimedOperation struct {
	fleetapp.ConnectorNativeObservationOperation
	t *regionalCapacityTimed
}

func (o regionalTimedOperation) Read(ctx context.Context, ordinal int) (value.ConnectorObservationNativeValue, error) {
	started := time.Now()
	calls, _ := o.t.stats.load()
	out, err := o.ConnectorNativeObservationOperation.Read(ctx, ordinal)
	o.t.report(fmt.Sprintf("native read %d", ordinal), started, calls, err)
	return out, err
}

type regionalTimedMetadata struct {
	inner *kube.ClusterObservationMetadata
	t     *regionalCapacityTimed
}

func (m regionalTimedMetadata) ObserveCluster(ctx context.Context, r value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	started := time.Now()
	calls, _ := m.t.stats.load()
	out, err := m.inner.ObserveCluster(ctx, r)
	m.t.report("metadata "+string(r.Purpose), started, calls, err)
	return out, err
}
