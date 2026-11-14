package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/contextstart"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// regionalContext holds the ADR-171 regional context-start inputs that need no
// enrolled connector process. The API process and its exchanges are built
// only once the connector credentials are active.
type regionalContext struct {
	podUID     string
	logsClient *kube.SavedLogClient
	c          regionalConfig
	rootID     string
	pool       value.OwnerPool
	roots      *x509.CertPool
	attester   *kube.ConnectorProcessAttester
	settings   contracts.ConnectorAPIContextSettings
	targets    *kube.PodTargets
	// peers re-resolves frozen Kubernetes packet peers for the running
	// recordings' membership verifiers (ADR-283 part 3) with its own client
	// and limiter, so verification never starves target resolution.
	peers     *kube.PodTargets
	collector *kube.ContextCollector
	output    regionalArtifactOutput
	history   objectstore.HistoryObjects
	verifier  *jose.APIContextWorkSignatures
	owners    *RegionalLifecycle
	source    *kube.ConnectorIdentitySource
}

// regionalOwnerPool converts the pinned hub owner configuration. Its pool must
// name the hub native listener of this installation.
func regionalOwnerPool(c regionalConfig, w contracts.OwnerConfiguration) (value.OwnerPool, error) {
	p := value.OwnerPool{InstallationID: w.InstallationID, ClusterID: w.ClusterID, IssuerEpoch: w.IssuerEpoch, Namespace: w.Namespace.Name, NamespaceUID: w.Namespace.UID, Service: w.Service.Name, ServiceUID: w.Service.UID, Deployment: w.Deployment.Name, DeploymentUID: w.Deployment.UID, ServiceAccount: w.ServiceAccount.Name, AccountUID: w.ServiceAccount.UID, Port: w.Port, NativePort: w.NativePort, NativeBootstrap: w.NativeBootstrap, NativeCandidateLimit: w.NativeCandidateLimit, OperationPort: w.OperationPort}
	if w.Format != contracts.OwnerConfigurationFormat || !p.Valid() || p.NativePort == 0 || p.InstallationID != c.binding.InstallationID || p.IssuerEpoch != c.binding.IssuerEpoch {
		return value.OwnerPool{}, mounts.ErrUnavailable
	}
	if _, _, err := mtls.OwnerTrustRoots(w.IssuerRoots, time.Now()); err != nil {
		return value.OwnerPool{}, mounts.ErrUnavailable
	}
	return p, nil
}

// storageCredentials reads one fixed write-only object credential file per call.
func storageCredentials(in *providerInputs, name string) aws.CredentialsProviderFunc {
	return func(ctx context.Context) (aws.Credentials, error) {
		var zero aws.Credentials
		b, err := in.read(ctx, name, 32<<10)
		if err != nil {
			return zero, mounts.ErrUnavailable
		}
		defer clear(b)
		c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(b))
		if err != nil || !identity.Text(c.AccessKeyID, 256) || !identity.Text(c.SecretAccessKey, 4096) || (c.SessionToken != "" && !identity.Text(c.SessionToken, 16384)) {
			return zero, mounts.ErrUnavailable
		}
		return aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Source: "protected-regional-projection"}, nil
	}
}

// newRegionalContext builds every input that does not need an enrolled
// process. Its observer is its own instance of the regional account's
// identity with its own 20 QPS limiter: sharing the lifecycle/source client
// let other regional reads starve the opening setup's original five seconds
// (installed native 53). It uses the kube.WithOpeningBurst limiter (ADR-208,
// installed native 55/57).
func newRegionalContext(ctx context.Context, c regionalConfig, in *providerInputs, podUID string, workload kube.ConnectorWorkload, source *kube.ConnectorIdentitySource, owners *RegionalLifecycle, credentials *mtls.ConnectorProcessCredentials) (*regionalContext, []func(), error) {
	var closers []func()
	x := *c.Executor
	control := cfg.NamespaceRef{Name: c.Namespace, UID: workload.NamespaceUID}
	token := contracts.ConnectorKubeTokenFile
	observer, err := kube.NewPermissionClient(kube.WithOpeningBurst(in.kubernetes(token)), c.ClusterID, control, time.Now)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	out := &regionalContext{c: c, rootID: c.rootID(), podUID: podUID, owners: owners, source: source}
	if out.pool, err = regionalOwnerPool(c, c.owners.Configuration); err != nil {
		return nil, closers, err
	}
	if out.roots, _, err = mtls.OwnerTrustRoots(c.owners.Configuration.IssuerRoots, time.Now()); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	if out.attester, err = kube.NewConnectorProcessAttester(observer, source, workload, regionalPodToken{in}); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	if out.settings, err = kube.ConnectorAPISettings(c.rootID(), c.binding, workload, c.ImageDigest); err != nil {
		return nil, closers, &fixedStepError{"settings", err}
	}
	if out.targets, err = kube.NewAPIContextTargets(observer); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	if x.Alertmanager != "" {
		alerts, err := kube.NewAlertmanager(x.Alertmanager)
		if err != nil {
			return nil, closers, mounts.ErrUnavailable
		}
		out.targets = out.targets.WithAlertmanager(alerts)
	}
	if len(x.IdentityMappings) > 0 {
		if out.targets, err = out.targets.WithIdentityMappings(x.IdentityMappings); err != nil {
			return nil, closers, mounts.ErrUnavailable
		}
	}
	if len(x.ProfileEndpoints) > 0 {
		// ADR-285: preview resolves Go profile endpoints in this region.
		if out.targets, err = out.targets.WithProfileEndpoints(x.ProfileEndpoints); err != nil {
			return nil, closers, mounts.ErrUnavailable
		}
	}
	verifier, err := kube.NewPermissionClient(kube.WithOpeningBurst(in.kubernetes(token)), c.ClusterID, control, time.Now)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	if out.peers, err = kube.NewAPIContextTargets(verifier); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	if out.collector, err = kube.NewAPIContextClient(in.kubernetes(token)); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	if out.logsClient, err = kube.NewSavedLogClient(in.kubernetes(token)); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	a := c.store
	storage, err := ownerHTTPNamed(a.Endpoint, a.ServerName, a.Roots)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	closers = append(closers, storage.CloseIdleConnections)
	store, err := objectstore.New(a.Endpoint, a.Region, a.Bucket, storageCredentials(in, contracts.ConnectorEvidenceFile), storage)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	closers = append(closers, store.Close)
	custody, err := store.ForCustody(a.StoreID)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	// History is a separate purpose-limited capability in the same qualified
	// backend/bucket. It never receives the raw evidence writer's credential.
	metadata, err := objectstore.New(a.Endpoint, a.Region, a.Bucket, storageCredentials(in, contracts.RegionalHistoryCredentialFile), storage)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	closers = append(closers, metadata.Close)
	out.history = objectstore.HistoryObjects{Store: metadata, StoreID: a.StoreID}
	// ADR-176: keysets are wrapped by the local key service, per attempt, with
	// this process's own connector client leaf.
	keyRoots, _, err := mtls.OwnerTrustRoots(c.keys.Roots, time.Now())
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	keyTransport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: keyRoots, ServerName: c.keys.ServerName, GetClientCertificate: credentials.GetClientCertificate}, DialContext: (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: -1}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 5 * time.Second, MaxConnsPerHost: 8, DisableCompression: true}
	closers = append(closers, keyTransport.CloseIdleConnections)
	out.output = regionalArtifactOutput{store: custody, endpoint: c.keys.Endpoint, scope: authorization.KeyScope{InstallationID: c.binding.InstallationID, Purpose: "artifact", KeyID: c.keys.KeyID}, client: &http.Client{Transport: keyTransport, Timeout: 5 * time.Second}, now: time.Now}
	out.output.recordings = NewConnectorRecordings(nil, out.collector, time.Now, eventLog(os.Stderr, "regional collection"))
	// Recovery is the hub's delegated read; the trust source only verifies.
	settings, err := kube.ConnectorWorkTrustSettings(c.offer, c.ClusterID)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	trust, err := kube.NewConnectorWorkTrust(observer, owners, c.ClusterID, settings)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	if out.verifier, err = jose.NewAPIContextWorkSignatures(trust, "", nil, time.Now); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	return out, closers, nil
}

// run builds the API process for the active connector credentials and serves
// outbound standby exchanges until ctx ends or a component fails.
func (r *regionalContext) run(ctx context.Context, credentials *mtls.ConnectorProcessCredentials) error {
	// Fixed stage names for the stop line; never inputs or API text.
	protected, err := kube.NewConnectorAPIExecutionProtection(r.attester, credentials, r.settings)
	if err != nil {
		return &fixedStepError{"execution-protection", err}
	}
	process, err := kube.NewConnectorAPIExecutionProcess(ctx, protected)
	if err != nil {
		return &fixedStepError{"execution-process", err}
	}
	client, err := mtls.NewRegionalContextStartClient(ctx, r.rootID, r.pool, r.roots, r.c.owners.Address, r.owners, credentials, process, r.c.Executor.Concurrency, time.Now)
	if err != nil {
		return &fixedStepError{"start-client", err}
	}
	output := r.output
	output.writerEpoch = process.ProcessEpoch()
	if output.recordings != nil {
		output.recordings.configureLogs(ctx, r.rootID, r.logsClient, r.podUID, process.ProcessEpoch())
		defer output.recordings.closeLogs()
	}
	local := contextstart.RegionalLocal{Process: process, Targets: reportedTargets{r.targets, timedEventLog(os.Stderr, "regional target answer"), r.output.recordings, timedEventLog(os.Stderr, "regional source snapshot refused")}, Output: output, Collector: r.collector, Source: r.source, Now: time.Now}
	local.History = &contextstart.HistoryLocal{Verifier: r.verifier, Effects: regionalHistoryObjects{objects: r.history, root: r.rootID, cluster: r.c.ClusterID, epoch: process.ProcessEpoch(), now: time.Now}, Report: timedEventLog(os.Stderr, "regional history timing")}
	if r.output.recordings != nil {
		local.Recordings = r.output.recordings
		local.Sources = &contextstart.SourceLocal{Verifier: r.verifier, Snapshots: r.output.recordings, Profiles: r.output.recordings, Recordings: r.output.recordings, Report: eventLog(os.Stderr, "regional source work refused")}
		if queue, ok := r.output.recordings.nodes.(contextstart.SourceQueue); ok {
			local.Sources.Queue = queue
		}
	}
	fmt.Fprintln(os.Stderr, "regional context start active")
	return RegionalContextStartConnections{Candidates: r.owners, Client: client, Verifier: reportedWorkVerifier{r.verifier, eventLog(os.Stderr, "regional work refused")}, Local: local, Report: eventLog(os.Stderr, "regional context standby refused"), ReportOpening: contextStartOpeningLog(os.Stderr)}.Run(ctx)
}

// regionalArtifactOutput prepares each attempt's output with a key sealer
// whose authority is that attempt (ADR-176). The sealer is never shared.
type regionalArtifactOutput struct {
	store    *objectstore.CustodyStore
	endpoint string
	scope    authorization.KeyScope
	client   *http.Client
	now      func() time.Time
	// recordings holds started manual recordings (ADR-248); nil without the
	// collector input, which refuses every recording.
	recordings  *ConnectorRecordings
	writerEpoch string
}

func (o regionalArtifactOutput) PrepareContext(ctx context.Context, e artifact.ContextExpectation) (evidence.PreparedContext, error) {
	seal, err := kms.NewRemoteSealer(o.endpoint, o.scope, e.Registration.Location.AttemptID, o.client)
	if err != nil {
		return nil, err
	}
	if e.Profile != nil {
		if o.recordings == nil || o.writerEpoch == "" {
			return nil, value.ErrUnavailable
		}
		if e.Registration.NativeLimit > artifact.FrameBytes {
			prepared, err := objectstore.PrepareOneShotProfileArtifact(ctx, o.store, seal, e, o.writerEpoch, o.now)
			if err != nil {
				return nil, err
			}
			return o.recordings.PrepareProfile(prepared, e), nil
		}
		producer, err := objectstore.NewArtifactProducer(o.store, seal, noJournal{}, o.now)
		if err != nil {
			return nil, err
		}
		prepared, err := producer.Prepare(ctx, e, "")
		if err != nil {
			return nil, err
		}
		return o.recordings.PrepareProfile(prepared, e), nil
	}
	if e.Logs != nil {
		if o.recordings == nil || o.writerEpoch == "" {
			return nil, value.ErrUnavailable
		}
		var prepared *objectstore.PreparedArtifact
		var err error
		if e.Registration.NativeLimit > artifact.FrameBytes {
			prepared, err = objectstore.PrepareOneShotLogsArtifact(ctx, o.store, seal, e, o.writerEpoch, o.now)
		} else {
			var producer *objectstore.ArtifactProducer
			producer, err = objectstore.NewArtifactProducer(o.store, seal, noJournal{}, o.now)
			if err == nil {
				prepared, err = producer.Prepare(ctx, e, "")
			}
		}
		if err != nil {
			return nil, err
		}
		return o.recordings.PrepareLogs(prepared, e), nil
	}
	if e.Recording != nil || e.Snapshot != nil {
		// ADR-248: one frame at most, so the artifact producer never needs
		// the SQL streaming journal the connector does not hold.
		if o.recordings == nil {
			return nil, value.ErrUnavailable
		}
		producer, err := objectstore.NewArtifactProducer(o.store, seal, noJournal{}, o.now)
		if err != nil {
			return nil, err
		}
		prepared, err := producer.Prepare(ctx, e, "")
		if err != nil {
			return nil, err
		}
		return o.recordings.Prepare(prepared, e), nil
	}
	producer, err := objectstore.NewContextProducer(o.store, seal, o.now)
	if err != nil {
		return nil, err
	}
	return producer.PrepareContext(ctx, e)
}

// reportedTargets logs the region's target-answer step durations.
type reportedTargets struct {
	*kube.PodTargets
	report     func(string, string)
	recordings *ConnectorRecordings
	// refusal receives a source snapshot refusal's fixed reason as the event
	// and a producer-owned count as payload; nil leaves it silent.
	refusal func(string, string)
}

// PacketRecorder answers the hub's ADR-248 availability query; a connector
// without the collector input answers unavailable.
func (t reportedTargets) PacketRecorder(ctx context.Context, r targets.RecorderRequest) (targets.RecorderAnswer, error) {
	if t.recordings == nil {
		return targets.RecorderAnswer{Outcome: targets.RecorderUnavailable}, nil
	}
	return t.recordings.PacketRecorder(ctx, r)
}

// ResolvePacketRecorder observes the exact Pod and availability under one
// original receiver proof, without a second query or namespace/Pod read.
func (t reportedTargets) ResolvePacketRecorder(ctx context.Context, r targets.Request) (targets.RecorderResolution, error) {
	return t.resolvePacketRecorder(ctx, r, false)
}

// ResolveSyscallRecorder is ResolvePacketRecorder for a finite syscall
// recording (B3): the same exact Pod with the syscall mechanism's answer.
func (t reportedTargets) ResolveSyscallRecorder(ctx context.Context, r targets.Request) (targets.RecorderResolution, error) {
	p, node, err := t.PodTargets.ResolvePacketPod(ctx, r)
	if err != nil {
		return targets.RecorderResolution{}, err
	}
	return t.packetTargetAvailability(ctx, p, node, false, collector.MechanismSyscall), nil
}

// ResolvePacketSource explicitly requests the source incarnation for a future
// sensitive dispatch. Existing metadata wire answers never include these facts.
func (t reportedTargets) ResolvePacketSource(ctx context.Context, r targets.Request) (targets.RecorderResolution, error) {
	return t.resolvePacketRecorder(ctx, r, true)
}

// ResolveArgumentSource requires syscall availability and the same exact Pod
// and node incarnation used by the finite argument observation issuer.
func (t reportedTargets) ResolveArgumentSource(ctx context.Context, r targets.Request) (targets.RecorderResolution, error) {
	p, node, err := t.PodTargets.ResolvePacketPod(ctx, r)
	if err != nil {
		return targets.RecorderResolution{}, err
	}
	return t.packetTargetAvailability(ctx, p, node, true, collector.MechanismSyscall), nil
}

func (t reportedTargets) resolvePacketRecorder(ctx context.Context, r targets.Request, includeSource bool) (targets.RecorderResolution, error) {
	p, node, err := t.PodTargets.ResolvePacketPod(ctx, r)
	if err != nil {
		return targets.RecorderResolution{}, err
	}
	return t.packetTargetAvailability(ctx, p, node, includeSource, collector.MechanismPacket), nil
}
func (t reportedTargets) packetTargetAvailability(ctx context.Context, p targets.PodResolution, node string, includeSource bool, mechanism collector.Mechanism) targets.RecorderResolution {
	answer := targets.RecorderAnswer{Outcome: targets.RecorderUnavailable}
	if node == "" {
		answer.Outcome = targets.RecorderNoNode
	} else if t.recordings != nil {
		if v, ok := t.recordings.nodes.NodeByName(node); ok && v.RecorderAvailable(mechanism) {
			answer.Outcome = targets.RecorderAvailable
			if !includeSource {
				return targets.RecorderResolution{Target: p, Recorder: answer}
			}
			// Keep both original intervals. Reading a fresh Pod never refreshes an
			// older authenticated node report, and availability never grants authority.
			observed := p.ObservedAt
			if v.ReportedAt.After(observed) {
				observed = v.ReportedAt
			}
			until := p.FreshUntil
			if nodeUntil := v.ReportedAt.Add(collector.StatusStaleAfter); nodeUntil.Before(until) {
				until = nodeUntil
			}
			if ctx != nil {
				if deadline, ok := ctx.Deadline(); ok && deadline.Before(until) {
					until = deadline
				}
			}
			source := targets.PacketSourceObservation{PodUID: p.Pin.UID, NodeUID: v.Identity.NodeUID, BootID: v.Identity.BootID, CollectorPodUID: v.Identity.PodUID, CollectorEpoch: v.Identity.Epoch, ObservedAt: observed, FreshUntil: until}
			if ctx != nil && ctx.Err() == nil && source.Valid(t.recordings.now()) {
				answer.Source = &source
			}
			return targets.RecorderResolution{Target: p, Recorder: answer}
		}
	}
	return targets.RecorderResolution{Target: p, Recorder: answer}
}

// ResolvePacketPeers refuses a peer resolution while the connector already
// verifies its maximum of running recordings with Kubernetes peers (ADR-283
// part 3), so preview and submission report the limit before anything is
// reserved; the start checks it again.
func (t reportedTargets) ResolvePacketPeers(ctx context.Context, r targets.PeerRequest) (targets.PeerResolution, error) {
	if t.recordings != nil && t.recordings.peerVerifiersFull() {
		return targets.PeerResolution{}, targets.ErrPeerVerifierBusy
	}
	return t.PodTargets.ResolvePacketPeers(ctx, r)
}

func (t reportedTargets) ReportAnswer(steps string) { t.report("answer", steps) }

// reportedWorkVerifier logs a refused work verification's fixed step.
type reportedWorkVerifier struct {
	verifier *jose.APIContextWorkSignatures
	report   func(string)
}

func (v reportedWorkVerifier) VerifyAPIContextWork(ctx context.Context, encoded []byte, receiver value.APIContextReceiver) (value.AuthenticatedAPIContextWork, error) {
	out, err := v.verifier.VerifyAPIContextWork(ctx, encoded, receiver)
	if err != nil {
		step := "other"
		var fixed interface{ FixedStep() string }
		if errors.As(err, &fixed) {
			step = fixed.FixedStep()
		}
		v.report(step)
	}
	return out, err
}

// ResolveProfileRecorder observes the original API target and current profile
// mechanism in the same bounded regional query, without probing the endpoint.
func (t reportedTargets) ResolveProfileRecorder(ctx context.Context, r targets.Request) (targets.RecorderResolution, error) {
	p, node, err := t.PodTargets.ResolvePacketPod(ctx, r)
	if err != nil {
		return targets.RecorderResolution{}, err
	}
	return t.packetTargetAvailability(ctx, p, node, false, collector.MechanismProfile), nil
}
