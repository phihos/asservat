package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ConnectorAPIExecutionProtection is a concrete composition, not an arbitrary
// process-reader callback. The executor's startup facts (its Helm-rendered
// workload, capacity account and image) add API capability to the exact
// current connector-owned Pod and public CSR.
type ConnectorAPIExecutionProtection struct {
	attester       *ConnectorProcessAttester
	credentials    *mtls.ConnectorProcessCredentials
	installed      contracts.ConnectorAPIContextSettings
	startup, image artifact.Digest
	reuse          connectorAPIProofState
}

func connectorAPIDigest(s string) (artifact.Digest, error) {
	var d artifact.Digest
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != s {
		return d, cfg.ErrInvalid
	}
	copy(d[:], b)
	if d == (artifact.Digest{}) {
		return d, cfg.ErrInvalid
	}
	return d, nil
}

// ConnectorAPISettings derives the executor's startup facts from the
// connector's own workload (UIDs read by name at start) and the image digest of its Helm values. Template, input and guard pins of
// the former installer are gone; Kubernetes RBAC protects the objects.
func ConnectorAPISettings(rootID string, binding fleet.PeerBinding, workload ConnectorWorkload, imageDigest string) (contracts.ConnectorAPIContextSettings, error) {
	projection := compiler.ProjectionDigest()
	s := contracts.ConnectorAPIContextSettings{Format: contracts.ConnectorAPIContextFormat, RootID: rootID, InstallationID: binding.InstallationID, ClusterID: binding.ClusterID, IssuerEpoch: binding.IssuerEpoch,
		Namespace: workload.Namespace, NamespaceUID: workload.NamespaceUID, Account: workload.Account, AccountUID: workload.AccountUID, Deployment: workload.Deployment, DeploymentUID: workload.DeploymentUID,
		ImageDigest: imageDigest, ProjectionDigest: hex.EncodeToString(projection[:]), WorkloadProtectionDigest: hex.EncodeToString(workload.Digest[:])}
	if !connectorAPISettingsValid(s) {
		return contracts.ConnectorAPIContextSettings{}, cfg.ErrInvalid
	}
	return s, nil
}

func connectorAPISettingsValid(p contracts.ConnectorAPIContextSettings) bool {
	if p.Format != contracts.ConnectorAPIContextFormat || len(p.Inputs) != 0 || p.StartGuard != (contracts.ConnectorAPIStartGuard{}) || p.TemplateDigest != "" || p.ConnectorRevision != (contracts.APIContextRevision{}) {
		return false
	}
	for _, id := range []string{p.RootID, p.InstallationID, p.ClusterID, p.IssuerEpoch, p.NamespaceUID, p.AccountUID, p.DeploymentUID} {
		if !authorization.UUID(id) {
			return false
		}
	}
	for _, name := range []string{p.Account, p.Deployment} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return false
		}
	}
	if len(validation.IsDNS1123Label(p.Namespace)) != 0 {
		return false
	}
	for _, s := range []string{p.ImageDigest, p.ProjectionDigest, p.WorkloadProtectionDigest} {
		if _, e := connectorAPIDigest(s); e != nil {
			return false
		}
	}
	projection, e := connectorAPIDigest(p.ProjectionDigest)
	return e == nil && projection == compiler.ProjectionDigest()
}

func NewConnectorAPIExecutionProtection(a *ConnectorProcessAttester, credentials *mtls.ConnectorProcessCredentials, installed contracts.ConnectorAPIContextSettings) (*ConnectorAPIExecutionProtection, error) {
	if a == nil || a.client == nil || credentials == nil || !connectorAPISettingsValid(installed) {
		return nil, cfg.ErrInvalid
	}
	w, s := a.workload, installed
	if s.ClusterID != a.client.clusterID || s.Namespace != w.Namespace || s.NamespaceUID != w.NamespaceUID || s.Deployment != w.Deployment || s.DeploymentUID != w.DeploymentUID || s.Account != w.Account || s.AccountUID != w.AccountUID || hex.EncodeToString(w.Digest[:]) != s.WorkloadProtectionDigest {
		return nil, cfg.ErrInvalid
	}
	image, _ := connectorAPIDigest(s.ImageDigest)
	return &ConnectorAPIExecutionProtection{attester: a, credentials: credentials, installed: s, startup: ConnectorAPIStartupDigest(s), image: image}, nil
}

// ConnectorAPIStartupDigest is the executor's startup pin, which the hub's
// catalog entry names. It binds only values both sides know from Helm: the
// cluster binding, the workload names and the image.
func ConnectorAPIStartupDigest(s contracts.ConnectorAPIContextSettings) artifact.Digest {
	bound, _ := json.Marshal(struct {
		Format, RootID, InstallationID, ClusterID, IssuerEpoch string
		Namespace, Account, Deployment                         string
		ImageDigest, ProjectionDigest                          string
	}{"asservat-connector-api-startup/v3", s.RootID, s.InstallationID, s.ClusterID, s.IssuerEpoch, s.Namespace, s.Account, s.Deployment, s.ImageDigest, s.ProjectionDigest})
	return sha256.Sum256(bound)
}

func (g *ConnectorAPIExecutionProtection) matchesProof(p fleet.ConnectorProcessProof) bool {
	s := g.installed
	c := p.Configuration.Profile
	b := p.Process.Binding
	return c.RootID == s.RootID && b.InstallationID == s.InstallationID && b.ClusterID == s.ClusterID && b.IssuerEpoch == s.IssuerEpoch && p.ProtectionDigest == g.attester.workload.Digest && c.Deployment.Namespace == s.Namespace && c.Deployment.ServiceAccount == s.Account && c.Deployment.Deployment == s.Deployment
}

// Read the exact objects named by the independently attested chain. Recompute
// its original full digest to prevent a later fetch from mixing another spec
// into that proof, then apply the separately accepted template/image pin.
func (g *ConnectorAPIExecutionProtection) workload(ctx context.Context, p fleet.ConnectorProcessProof) error {
	s := g.installed
	r := &OwnerEndpoints{client: g.attester.client}
	d, e := ownerResource[apps.Deployment](r, ctx, "/apis/apps/v1/namespaces/"+s.Namespace+"/deployments/"+s.Deployment, "apps/v1", "Deployment")
	if e != nil || !ownerMetadata(d.ObjectMeta, s.Namespace, s.Deployment, s.DeploymentUID) {
		return connectorAPIStage("deployment", cfg.ErrChanged)
	}
	rs, e := ownerResource[apps.ReplicaSet](r, ctx, "/apis/apps/v1/namespaces/"+s.Namespace+"/replicasets/"+p.ReplicaSet, "apps/v1", "ReplicaSet")
	if e != nil || !ownerMetadata(rs.ObjectMeta, s.Namespace, p.ReplicaSet, p.ReplicaSetUID) {
		return connectorAPIStage("replicaset", cfg.ErrChanged)
	}
	pod, e := ownerResource[core.Pod](r, ctx, "/api/v1/namespaces/"+s.Namespace+"/pods/"+p.Pod, "v1", "Pod")
	if e != nil || !ownerMetadata(pod.ObjectMeta, s.Namespace, p.Pod, p.Process.PodUID) || pod.Status.Phase != core.PodPending && pod.Status.Phase != core.PodRunning {
		return connectorAPIStage("pod", cfg.ErrChanged)
	}
	raw, e := json.Marshal(struct {
		DeploymentPin            fleet.ConnectorDeployment
		PodUID, ReplicaSetUID    string
		Pod                      core.PodSpec
		ReplicaSet               apps.ReplicaSetSpec
		Deployment               apps.DeploymentSpec
		Labels                   map[string]string
		PodOwners, ReplicaOwners []meta.OwnerReference
	}{p.Configuration.Profile.Deployment, p.Process.PodUID, p.ReplicaSetUID, pod.Spec, rs.Spec, d.Spec, pod.Labels, pod.OwnerReferences, rs.OwnerReferences})
	if e != nil || len(raw) > 128<<10 {
		return cfg.ErrUnavailable
	}
	canonical := jsontext.Value(raw)
	if canonical.Canonicalize() != nil {
		return cfg.ErrUnavailable
	}
	h := sha256.New()
	h.Write([]byte("asservat-connector-process-workload/v1\x00"))
	h.Write(canonical)
	var digest artifact.Digest
	copy(digest[:], h.Sum(nil))
	if digest != p.WorkloadDigest {
		return connectorAPIStage("workload-digest", cfg.ErrChanged)
	}
	return nil
}

// connectorAPIStage names the executor check that failed, for the regional
// process's diagnostic line: fixed names only, never inputs or API text.
func connectorAPIStage(step string, err error) error {
	if err == nil {
		return nil
	}
	return &connectorAPIStepError{step: step, err: err}
}

type connectorAPIStepError struct {
	phase string    // closed cold-proof code, separate from the older elapsed trace
	until time.Time // diagnostic only: earliest original bound already learned
	step  string
	err   error
}

func (e *connectorAPIStepError) ContextStartSetupStep() string     { return e.phase }
func (e *connectorAPIStepError) ContextStartSetupUntil() time.Time { return e.until }

func (e *connectorAPIStepError) Error() string { return "connector API " + e.step }
func (e *connectorAPIStepError) Unwrap() error { return e.err }
func (e *connectorAPIStepError) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}

func (g *ConnectorAPIExecutionProtection) produceProof(ctx context.Context) (connectorAPIProof, error) {
	if g == nil || ctx == nil || ctx.Err() != nil {
		return connectorAPIProof{}, cfg.ErrUnavailable
	}
	start := g.attester.client.now()
	// until bounds this proof's reads (five seconds); the completed proof is
	// used for the ADR-311 recheck interval, never past the owned process's
	// run end or certificate.
	until := start.Add(5 * time.Second)
	valid := start.Add(identity.AuthorityRecheckInterval)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	// Each failed check names itself and the elapsed share of the original
	// five seconds, for the regional process's diagnostic line.
	// The completed checks' marks profile where the five seconds went.
	var marks []string
	at := func(name string) string {
		return name + "@" + g.attester.client.now().Sub(start).Round(10*time.Millisecond).String()
	}
	mark := func(name string) { marks = append(marks, at(name)) }
	stage := func(name string, err error) error {
		return &connectorAPIStepError{phase: name, until: until, step: at(name) + " after [" + strings.Join(marks, " ") + "]", err: err}
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	// ADR-199: one source read opens the proof; the owned process and the
	// attestation are checked against it, and one read closes it below.
	open, e := g.attester.source.ReadConnectorIdentitySource(call)
	if e != nil || !open.Valid(g.attester.client.now()) {
		return connectorAPIProof{}, stage("source-open", errors.Join(cfg.ErrUnavailable, e))
	}
	until = identity.Earlier(until, open.Observation.FreshUntil)
	call, c0 := context.WithDeadline(call, until)
	defer c0()
	mark("source-open")
	owned, e := g.credentials.ObserveConnectorProcessAt(call, open)
	if e != nil {
		return connectorAPIProof{}, stage("owned-process", e)
	}
	until = identity.Earlier(until, owned.ValidUntil)
	valid = identity.Earlier(valid, owned.HardUntil())
	call, c1 := context.WithDeadline(call, until)
	defer c1()
	mark("owned-process")
	proof, e := g.attester.ReadConnectorProcessProofAt(call, owned.Request, open)
	if e != nil {
		return connectorAPIProof{}, stage("process-proof", e)
	}
	if !proof.Valid(g.attester.client.now()) || !g.matchesProof(proof) || !proof.Configuration.SameSource(owned.Configuration) || owned.Registration.Certificate.PublicKeyDigest != proof.ClientKeyDigest {
		return connectorAPIProof{}, stage("process-match", cfg.ErrChanged)
	}
	until = identity.Earlier(until, proof.FreshUntil)
	call, c2 := context.WithDeadline(call, until)
	defer c2()
	mark("process-proof")
	if e = g.workload(call, proof); e != nil {
		return connectorAPIProof{}, stage("workload", e)
	}
	mark("workload")
	closed, e := g.attester.source.ReadConnectorIdentitySource(call)
	if e != nil || !closed.Valid(g.attester.client.now()) || closed.Roles != open.Roles || !closed.Observation.SameSource(open.Observation) {
		return connectorAPIProof{}, stage("source-close", cfg.ErrChanged)
	}
	until = identity.Earlier(until, closed.Observation.FreshUntil)
	mark("source-close")
	// ADR-199 decision 5: the close is local; the opening hub registration's
	// original FreshUntil still bounds the proof.
	final, e := g.credentials.ConfirmConnectorProcessAt(call, owned, closed)
	if e != nil || final.Request.Process != owned.Request.Process || final.Registration.Certificate != owned.Registration.Certificate || !final.Configuration.SameSource(owned.Configuration) {
		return connectorAPIProof{}, stage("owned-process-after", cfg.ErrChanged)
	}
	until = identity.Earlier(until, final.ValidUntil)
	valid = identity.Earlier(valid, final.HardUntil())
	if call.Err() != nil || !identity.Fresh(start, until, g.attester.client.now(), 5*time.Second) || !proof.Valid(g.attester.client.now()) {
		return connectorAPIProof{}, stage("fresh", cfg.ErrUnavailable)
	}
	closed.Observation.Profile = closed.Observation.Profile.Clone()
	return connectorAPIProof{proof: proof.Clone(), owned: owned, source: closed, observedAt: start, validUntil: valid}, nil
}

type ConnectorAPIExecutionProcess struct {
	guard     *ConnectorAPIExecutionProtection
	parent    context.Context
	connector fleet.ConnectorProcessIdentity
	binding   value.APIProcessBinding
}

func NewConnectorAPIExecutionProcess(ctx context.Context, g *ConnectorAPIExecutionProtection) (*ConnectorAPIExecutionProcess, error) {
	if ctx == nil || g == nil {
		return nil, value.ErrInvalid
	}
	proof, e := g.current(ctx)
	b := proof.proof.Process
	if e != nil {
		return nil, e
	}
	epoch := uuid.NewString()
	if epoch == b.ProcessEpoch {
		return nil, value.ErrUnavailable
	}
	s := g.installed
	return &ConnectorAPIExecutionProcess{g, ctx, b, value.APIProcessBinding{InstallationID: s.InstallationID, ClusterID: s.ClusterID, IssuerEpoch: s.IssuerEpoch, NamespaceUID: s.NamespaceUID, AccountUID: s.AccountUID, PodUID: b.PodUID, ProcessEpoch: epoch, StartupDigest: g.startup, ImageDigest: g.image}}, nil
}

// ProcessEpoch is the immutable local writer pin, not a current observation or
// authorization. Effects still require the native receiver and signed operation.
func (p *ConnectorAPIExecutionProcess) ProcessEpoch() string {
	if p == nil {
		return ""
	}
	return p.binding.ProcessEpoch
}

func (p *ConnectorAPIExecutionProcess) ReadAPIProcess(ctx context.Context) (value.APIProcessObservation, error) {
	out, _, err := p.readAPIProcess(ctx)
	return out, err
}

// ReadAPIProcessConnector exposes only the owned connector observation that
// this same concrete native proof already checked. It cannot borrow another
// credentials instance or renew the underlying cached proof's original bounds.
func (p *ConnectorAPIExecutionProcess) ReadAPIProcessConnector(ctx context.Context, credentials *mtls.ConnectorProcessCredentials) (value.APIProcessObservation, mtls.ConnectorProcessObservation, error) {
	if p == nil || p.guard == nil || credentials == nil || credentials != p.guard.credentials {
		return value.APIProcessObservation{}, mtls.ConnectorProcessObservation{}, value.ErrUnavailable
	}
	return p.readAPIProcess(ctx)
}

func (p *ConnectorAPIExecutionProcess) readAPIProcess(ctx context.Context) (value.APIProcessObservation, mtls.ConnectorProcessObservation, error) {
	var zero value.APIProcessObservation
	if p == nil || ctx == nil || p.parent.Err() != nil {
		return zero, mtls.ConnectorProcessObservation{}, value.ErrUnavailable
	}
	// The enclosing observation owns its original recheck interval (ADR-311).
	// The guard's own proof keeps its earlier start and interval. The caller's
	// deadline bounds this read's work by cancellation, not the validity of
	// the reused proof: the proof's own reads keep their five-second bound.
	start := p.guard.attester.client.now()
	call, cancel := context.WithDeadline(context.WithoutCancel(ctx), start.Add(identity.AuthorityRecheckInterval))
	defer cancel()
	callerDone := make(chan struct{})
	stopCaller := context.AfterFunc(ctx, func() { cancel(); close(callerDone) })
	defer func() {
		if !stopCaller() {
			<-callerDone
		}
	}()
	done := make(chan struct{})
	stop := context.AfterFunc(p.parent, func() { cancel(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	proof, e := p.guard.current(call)
	b, until := proof.proof.Process, proof.validUntil
	if e != nil || b != p.connector {
		return zero, mtls.ConnectorProcessObservation{}, value.ErrUnavailable
	}
	out := value.APIProcessObservation{Binding: p.binding, CheckedAt: proof.observedAt, ValidUntil: until}
	if call.Err() != nil || ctx.Err() != nil || p.parent.Err() != nil || !out.Valid(p.guard.attester.client.now()) {
		return zero, mtls.ConnectorProcessObservation{}, value.ErrUnavailable
	}
	owned := proof.owned
	owned.Request.ClientCSRDER = bytes.Clone(owned.Request.ClientCSRDER)
	owned.Request.ServerCSRDER = bytes.Clone(owned.Request.ServerCSRDER)
	owned.Configuration.Profile = owned.Configuration.Profile.Clone()
	owned.ValidUntil = identity.Earlier(owned.ValidUntil, until)
	return out, owned, nil
}
