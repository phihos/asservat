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
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/contextstart"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// regionalContext holds the ADR-171 regional context-start inputs that need no
// enrolled connector process. The API process and its exchanges are built
// only once the connector credentials are active.
type regionalContext struct {
	c         contracts.RegionalAPIContext
	rootID    string
	pool      value.OwnerPool
	roots     *x509.CertPool
	attester  *kube.ConnectorProcessAttester
	settings  *kube.ConnectorAPISettingsProtection
	capacity  *kube.PermissionClient
	journal   *kube.StartJournal
	targets   *kube.PodTargets
	collector *kube.ContextCollector
	output    regionalArtifactOutput
	verifier  *jose.APIContextWorkSignatures
	owners    *RegionalLifecycle
	source    *kube.ConnectorIdentitySource
}

func validRegionalAPIContext(c contracts.RegionalDeployment) bool {
	a := c.APIContext
	if a == nil {
		return true
	}
	guard := func(g contracts.OwnerDeploymentGuard) bool {
		return identity.Text(g.Name, 253) && authorization.UUID(g.PolicyUID) && authorization.UUID(g.BindingUID) && identity.Text(g.BindingResourceVersion, 128) && g.PolicyGeneration >= 1 && g.PolicyGeneration < 1<<53 && len(g.Administrators) >= 1 && len(g.Administrators) <= 32
	}
	reference := func(r contracts.WorkerObjectReference) bool {
		return identity.Text(r.Name, 253) && authorization.UUID(r.UID)
	}
	if a.Starts.CapacityAudience == "" || !identity.Text(a.Settings, 253) || !guard(a.SettingsGuard) || !reference(a.WorkTrust) || !guard(a.WorkTrustGuard) || !reference(a.Starts.CapacityAccount) || !reference(a.Starts.ExecutionAccount) || a.Concurrency < 1 || a.Concurrency > 16 {
		return false
	}
	if _, err := ownerDeploymentStarts(&a.Starts); err != nil {
		return false
	}
	s := a.EvidenceStore
	k := a.KeyService
	if !ownerEndpoint(s.Endpoint) || !identity.Text(s.Region, 128) || !identity.Text(s.Bucket, 63) || !authorization.UUID(s.StoreID) || !ownerEndpoint(k.Endpoint) || !(authorization.KeyScope{InstallationID: c.InstallationID, Purpose: "artifact", KeyID: k.KeyID}).Valid() {
		return false
	}
	if !ownerDialAddress(a.Owners.Address) || a.Alertmanager != "" && !kube.AlertmanagerURL(a.Alertmanager) {
		return false
	}
	_, err := regionalOwnerPool(c, a.Owners.Configuration)
	return err == nil && a.TrustSettings.ClusterID == c.ClusterID
}

// regionalOwnerPool converts the pinned hub owner configuration. Its pool must
// name the hub native listener of this installation.
func regionalOwnerPool(c contracts.RegionalDeployment, w contracts.OwnerConfiguration) (value.OwnerPool, error) {
	p := value.OwnerPool{InstallationID: w.InstallationID, ClusterID: w.ClusterID, IssuerEpoch: w.IssuerEpoch, Namespace: w.Namespace.Name, NamespaceUID: w.Namespace.UID, Service: w.Service.Name, ServiceUID: w.Service.UID, Deployment: w.Deployment.Name, DeploymentUID: w.Deployment.UID, ServiceAccount: w.ServiceAccount.Name, AccountUID: w.ServiceAccount.UID, Port: w.Port, NativePort: w.NativePort, NativeBootstrap: w.NativeBootstrap, NativeCandidateLimit: w.NativeCandidateLimit, OperationPort: w.OperationPort}
	if w.Format != contracts.OwnerConfigurationFormat || !p.Valid() || p.NativePort == 0 || p.InstallationID != c.InstallationID || p.IssuerEpoch != c.IssuerEpoch {
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
// process. Like regional capacity, its observer/probe are its own instances of
// the regional account's identities, each with its own 20 QPS limiter:
// sharing the lifecycle/source client let other regional reads starve the
// opening setup's original five seconds (installed native 53). They use the
// kube.WithOpeningBurst limiter (ADR-208, installed native 55/57).
func newRegionalContext(ctx context.Context, c contracts.RegionalDeployment, in *providerInputs, podUID string, workload cfg.OwnerWorkloadAdministration, sourcePlan cfg.ConfigMapAdministration, binding value.PeerBinding, owners *RegionalLifecycle, credentials *mtls.ConnectorProcessCredentials) (*regionalContext, []func(), error) {
	var closers []func()
	a := *c.APIContext
	control := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	observer, err := kube.NewPermissionClient(kube.WithOpeningBurst(in.kubernetes("kube-observer.token")), c.ClusterID, control, time.Now)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	probe, err := kube.NewPermissionClient(kube.WithOpeningBurst(in.kubernetes("kube-probe.token")), c.ClusterID, control, time.Now)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	guard, err := kube.NewOwnerWorkloadProtection(observer, probe, workload, regionalPin(c.WorkloadGuard))
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	protection, err := kube.NewConnectorIdentityProtection(observer, probe, sourcePlan, regionalPin(c.SourceGuard))
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	source, err := kube.NewConnectorIdentitySource(observer, protection, c.Source.Name, c.Source.UID, c.PermissionRootID, binding)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	out := &regionalContext{c: a, rootID: c.PermissionRootID, owners: owners, source: source}
	if out.pool, err = regionalOwnerPool(c, a.Owners.Configuration); err != nil {
		return nil, closers, err
	}
	if out.roots, _, err = mtls.OwnerTrustRoots(a.Owners.Configuration.IssuerRoots, time.Now()); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	if out.attester, err = kube.NewConnectorProcessAttester(observer, source, guard, regionalPodToken{in}); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	configMap := func(g contracts.OwnerDeploymentGuard, name string) cfg.ConfigMapAdministration {
		return cfg.ConfigMapAdministration{Name: g.Name, SourceName: name, ControlNamespace: control, Administrators: regionalActors(g.Administrators)}
	}
	if out.settings, err = kube.NewConnectorAPISettingsProtection(observer, probe, configMap(a.SettingsGuard, a.Settings), regionalPin(a.SettingsGuard)); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	// ADR-175: the capacity token is minted in memory by this Pod's own
	// account, bound to this Pod, never mounted or written.
	capacity, err := kube.NewCapacityTokens(ctx, observer, a.Starts.CapacityAccount.Name, a.Starts.CapacityAudience, podUID)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	closers = append(closers, capacity.Close)
	if out.capacity, err = kube.NewPermissionClient(in.kubernetesToken(capacity.Token), c.ClusterID, control, time.Now); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	// The execution account's own Pod-bound token consumes Ready starts.
	if out.journal, err = kube.NewStartJournal(in.kubernetes("kube-observer.token"), c.ClusterID, control, time.Now); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	if out.targets, err = kube.NewAPIContextTargets(observer); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	if a.Alertmanager != "" {
		alerts, err := kube.NewAlertmanager(a.Alertmanager)
		if err != nil {
			return nil, closers, mounts.ErrUnavailable
		}
		out.targets = out.targets.WithAlertmanager(alerts)
	}
	if out.collector, err = kube.NewAPIContextClient(in.kubernetes("kube-observer.token")); err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	storage, err := ownerHTTP(a.EvidenceStore.Endpoint, a.EvidenceStore.Roots)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	closers = append(closers, storage.CloseIdleConnections)
	store, err := objectstore.New(a.EvidenceStore.Endpoint, a.EvidenceStore.Region, a.EvidenceStore.Bucket, storageCredentials(in, "evidence-storage.json"), storage)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	closers = append(closers, store.Close)
	custody, err := store.ForCustody(a.EvidenceStore.StoreID)
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	// ADR-176: keysets are wrapped by the local key service, per attempt, with
	// this process's own connector client leaf.
	keyRoots, _, err := mtls.OwnerTrustRoots(a.KeyService.Roots, time.Now())
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	keyTransport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: keyRoots, GetClientCertificate: credentials.GetClientCertificate}, DialContext: (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: -1}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 5 * time.Second, MaxConnsPerHost: 8, DisableCompression: true}
	closers = append(closers, keyTransport.CloseIdleConnections)
	out.output = regionalArtifactOutput{store: custody, endpoint: a.KeyService.Endpoint, scope: authorization.KeyScope{InstallationID: c.InstallationID, Purpose: "artifact", KeyID: a.KeyService.KeyID}, client: &http.Client{Transport: keyTransport, Timeout: 5 * time.Second}, now: time.Now}
	trustGuard, err := kube.NewAPIContextWorkTrustProtection(observer, probe, configMap(a.WorkTrustGuard, a.WorkTrust.Name), regionalPin(a.WorkTrustGuard))
	if err != nil {
		return nil, closers, mounts.ErrUnavailable
	}
	// Recovery is the hub's delegated read; the trust source only verifies.
	trust, err := kube.NewAPIContextWorkTrustSource(observer, trustGuard, owners, a.WorkTrust.Name, a.WorkTrust.UID, a.TrustSettings)
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
	a := r.c
	// ADR-196 decision 7: the settings are read by name; the hub's pinned
	// StartupDigest binds the exact object at every start.
	// Fixed stage names for the stop line; never inputs or API text.
	installed, uid, version, err := r.settings.ReadSettings(ctx)
	if err != nil {
		return &fixedStepError{"settings-read", err}
	}
	protected, err := kube.NewConnectorAPIExecutionProtection(r.attester, credentials, r.settings, a.Settings, uid, version, installed)
	if err != nil {
		return &fixedStepError{"execution-protection", err}
	}
	process, err := kube.NewConnectorAPIExecutionProcess(ctx, protected)
	if err != nil {
		return &fixedStepError{"execution-process", err}
	}
	preparer, err := kube.NewConnectorAPIStartPreparer(process, r.capacity)
	if err != nil {
		return &fixedStepError{"start-preparer", err}
	}
	client, err := mtls.NewRegionalContextStartClient(ctx, r.rootID, r.pool, r.roots, a.Owners.Address, r.owners, credentials, process, a.Concurrency, time.Now)
	if err != nil {
		return &fixedStepError{"start-client", err}
	}
	local := contextstart.RegionalLocal{Process: process, Targets: reportedTargets{r.targets, timedEventLog(os.Stderr, "regional target answer")}, Local: preparer, Starts: r.journal, Output: r.output, Collector: r.collector, Source: r.source, Now: time.Now}
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
}

func (o regionalArtifactOutput) PrepareContext(ctx context.Context, e artifact.ContextExpectation) (evidence.PreparedContext, error) {
	seal, err := kms.NewRemoteSealer(o.endpoint, o.scope, e.Registration.Location.AttemptID, o.client)
	if err != nil {
		return nil, err
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
	report func(string, string)
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
