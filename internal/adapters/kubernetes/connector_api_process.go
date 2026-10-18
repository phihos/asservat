package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"slices"
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
	admission "k8s.io/api/admissionregistration/v1"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const connectorAPISettingsDenial = "Asservat connector API context profile administrator is required."

type ConnectorAPISettingsProtection struct{ *configMapProtection }

func ConnectorAPISettingsAdmission(p cfg.ConfigMapAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	return configMapAdmission(p, "protected-connector-api-context", connectorAPISettingsDenial)
}
func NewConnectorAPISettingsProtection(observer, probe *PermissionClient, p cfg.ConfigMapAdministration, pin GuardPin) (*ConnectorAPISettingsProtection, error) {
	g, e := newConfigMapProtection(observer, probe, p, pin, "protected-connector-api-context", connectorAPISettingsDenial)
	if e != nil {
		return nil, e
	}
	return &ConnectorAPISettingsProtection{g}, nil
}

// ConnectorAPIExecutionProtection is a concrete composition, not an arbitrary
// process-reader callback. The installed projection and its own denial proof
// add API capability to the exact current connector-owned Pod and public CSR.
type ConnectorAPIExecutionProtection struct {
	attester                             *ConnectorProcessAttester
	credentials                          *mtls.ConnectorProcessCredentials
	settings                             *ConnectorAPISettingsProtection
	name, uid, rv                        string
	installed                            contracts.ConnectorAPIContextSettings
	canonical                            []byte
	startup, image, template, projection artifact.Digest
	reuse                                connectorAPIProofState
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
func connectorAPISettingsValid(p contracts.ConnectorAPIContextSettings) bool {
	if p.Format != contracts.ConnectorAPIContextFormat {
		return false
	}
	for _, id := range []string{p.RootID, p.InstallationID, p.ClusterID, p.IssuerEpoch, p.NamespaceUID, p.AccountUID, p.DeploymentUID, p.ConnectorRevision.UID, p.CapacityAccountUID, p.StartGuard.PolicyUID, p.StartGuard.BindingUID} {
		if !authorization.UUID(id) {
			return false
		}
	}
	for _, name := range []string{p.Account, p.Deployment, p.CapacityAccount, p.StartGuard.Name} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return false
		}
	}
	if len(validation.IsDNS1123Label(p.Namespace)) != 0 || p.Account == p.CapacityAccount || p.AccountUID == p.CapacityAccountUID || p.ConnectorRevision.Generation < 1 || p.ConnectorRevision.Generation > 2147483647 || p.StartGuard.PolicyGeneration < 1 || !identity.Text(p.StartGuard.BindingResourceVersion, 128) {
		return false
	}
	for _, s := range []string{p.ImageDigest, p.TemplateDigest, p.ProjectionDigest, p.WorkloadProtectionDigest, p.ConnectorRevision.Digest} {
		if _, e := connectorAPIDigest(s); e != nil {
			return false
		}
	}
	projection, e := connectorAPIDigest(p.ProjectionDigest)
	if e != nil || projection != compiler.ProjectionDigest() {
		return false
	}
	if len(p.Inputs) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, in := range p.Inputs {
		key := in.Kind + "/" + in.Name
		if in.Kind != "ConfigMap" && in.Kind != "Secret" || len(validation.IsDNS1123Subdomain(in.Name)) != 0 || !authorization.UUID(in.UID) || !identity.Text(in.ResourceVersion, 128) || seen[key] || (in.Kind == "Secret") != in.DedicatedToAPI {
			return false
		}
		seen[key] = true
	}
	return true
}
func NewConnectorAPIExecutionProtection(a *ConnectorProcessAttester, credentials *mtls.ConnectorProcessCredentials, settings *ConnectorAPISettingsProtection, name, uid, rv string, installed contracts.ConnectorAPIContextSettings) (*ConnectorAPIExecutionProtection, error) {
	if a == nil || a.client == nil || a.protection == nil || credentials == nil || settings == nil || settings.configMapProtection == nil || settings.observer != a.client || settings.plan.SourceName != name || !installationRefValid(name, uid) || !identity.Text(rv, 128) || !connectorAPISettingsValid(installed) {
		return nil, cfg.ErrInvalid
	}
	p := a.protection.plan
	s := installed
	if s.ClusterID != a.client.clusterID || s.Namespace != a.client.control.Name || s.NamespaceUID != a.client.control.UID || p.Deployment != s.Deployment || p.DeploymentUID != s.DeploymentUID || p.APIContextStarts == nil || p.APIContextStarts.CapacityAccount != s.CapacityAccount || p.APIContextStarts.CapacityAccountUID != s.CapacityAccountUID || p.APIContextStarts.ExecutionAccount != s.Account || p.APIContextStarts.ExecutionAccountUID != s.AccountUID || hex.EncodeToString(a.protection.digest[:]) != s.WorkloadProtectionDigest {
		return nil, cfg.ErrInvalid
	}
	// An overlapping namespace denial must not impersonate the independently
	// pinned source policy: only the exact named dry-run probe passes it.
	probeAllowed := false
	for _, p := range p.ConfigurationProbes {
		if p.ConfigMap == name {
			probeAllowed = true
		}
	}
	if !probeAllowed {
		return nil, cfg.ErrInvalid
	}
	s.Inputs = slices.Clone(s.Inputs)
	startup, canonical, e := ConnectorAPIStartupDigest(settings.digest, uid, rv, s)
	if e != nil {
		return nil, e
	}
	image, _ := connectorAPIDigest(s.ImageDigest)
	template, _ := connectorAPIDigest(s.TemplateDigest)
	projection, _ := connectorAPIDigest(s.ProjectionDigest)
	return &ConnectorAPIExecutionProtection{attester: a, credentials: credentials, settings: settings, name: name, uid: uid, rv: rv, installed: s, canonical: canonical, startup: startup, image: image, template: template, projection: projection}, nil
}

// ConnectorAPIStartupDigest is the executor's startup pin, which the hub's
// catalog entry names: the settings ConfigMap's UID and version, its guard
// digest and the canonical settings. The regional installer prints the same
// value in its join record (ADR-196 decision 7).
func ConnectorAPIStartupDigest(guard artifact.Digest, uid, rv string, installed contracts.ConnectorAPIContextSettings) (artifact.Digest, []byte, error) {
	canonical, e := contracts.EncodeConnectorAPIContextSettings(installed)
	if e != nil {
		return artifact.Digest{}, nil, e
	}
	bound, _ := json.Marshal(struct {
		Format, SourceUID, SourceVersion string
		SourceProtection                 artifact.Digest
		Settings                         json.RawMessage
	}{"asservat-connector-api-startup/v1", uid, rv, guard, canonical})
	return sha256.Sum256(bound), canonical, nil
}

// ReadSettings returns the guarded, immutable settings ConfigMap's settings,
// UID and version, read by name at process start (ADR-196 decision 7). The
// execution protection then rechecks the exact object on every start.
func (g *ConnectorAPISettingsProtection) ReadSettings(ctx context.Context) (contracts.ConnectorAPIContextSettings, string, string, error) {
	var zero contracts.ConnectorAPIContextSettings
	if g == nil || g.configMapProtection == nil || ctx == nil {
		return zero, "", "", cfg.ErrInvalid
	}
	object, e := g.proveObject(ctx)
	if e != nil {
		return zero, "", "", e
	}
	if object.Immutable == nil || !*object.Immutable || len(object.Data) != 1 || len(object.BinaryData) != 0 || !authorization.UUID(string(object.UID)) || !identity.Text(object.ResourceVersion, 128) {
		return zero, "", "", cfg.ErrChanged
	}
	s, e := contracts.DecodeConnectorAPIContextSettings([]byte(object.Data["connector-api-context.json"]))
	if e != nil {
		return zero, "", "", cfg.ErrChanged
	}
	return s, string(object.UID), object.ResourceVersion, nil
}
func (g *ConnectorAPIExecutionProtection) snapshot(ctx context.Context) error {
	data, ref, e := g.attester.client.installationConfigMode(ctx, g.name, g.uid, true)
	if e != nil || len(data) != 1 || ref.UID != g.uid || ref.ResourceVersion != g.rv {
		return cfg.ErrUnavailable
	}
	p, e := contracts.DecodeConnectorAPIContextSettings([]byte(data["connector-api-context.json"]))
	if e != nil {
		return cfg.ErrChanged
	}
	b, e := contracts.EncodeConnectorAPIContextSettings(p)
	if e != nil || !bytes.Equal(b, g.canonical) {
		return cfg.ErrChanged
	}
	return nil
}
func (g *ConnectorAPIExecutionProtection) matchesProof(p fleet.ConnectorProcessProof) bool {
	s := g.installed
	c := p.Configuration.Profile
	b := p.Process.Binding
	rev, _ := connectorAPIDigest(s.ConnectorRevision.Digest)
	return c.RootID == s.RootID && b.InstallationID == s.InstallationID && b.ClusterID == s.ClusterID && b.IssuerEpoch == s.IssuerEpoch && c.Revision == (identity.Revision{UID: s.ConnectorRevision.UID, Generation: s.ConnectorRevision.Generation, Digest: rev}) && p.ProtectionDigest == g.attester.protection.digest && c.Deployment.Namespace == s.Namespace && c.Deployment.NamespaceUID == s.NamespaceUID && c.Deployment.ServiceAccount == s.Account && c.Deployment.AccountUID == s.AccountUID && c.Deployment.Deployment == s.Deployment && c.Deployment.DeploymentUID == s.DeploymentUID
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
	if e = connectorAPITemplateMatch(&d, &rs, &pod, g.template, g.image); e != nil {
		return connectorAPIStage("template", e)
	}
	return connectorAPIStage("inputs", g.inputs(ctx, pod.Spec))
}

// connectorAPIStage names the executor check that failed, for the regional
// process's diagnostic line: fixed names only, never inputs or API text.
func connectorAPIStage(step string, err error) error {
	if err == nil {
		return nil
	}
	return &connectorAPIStepError{step, err}
}

type connectorAPIStepError struct {
	step string
	err  error
}

func (e *connectorAPIStepError) Error() string { return "connector API " + e.step }
func (e *connectorAPIStepError) Unwrap() error { return e.err }
func (e *connectorAPIStepError) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}

func (g *ConnectorAPIExecutionProtection) executionAccount(ctx context.Context, p fleet.ConnectorProcessProof) error {
	s := g.installed
	raw, e := g.attester.client.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	var who auth.SelfSubjectReview
	if e != nil || strictGuardJSON(raw, &who) != nil || who.Status.UserInfo.Username != "system:serviceaccount:"+s.Namespace+":"+s.Account || who.Status.UserInfo.UID != s.AccountUID {
		return cfg.ErrUnavailable
	}
	for key, want := range map[string]string{"authentication.kubernetes.io/pod-name": p.Pod, "authentication.kubernetes.io/pod-uid": p.Process.PodUID} {
		v := who.Status.UserInfo.Extra[key]
		if len(v) != 1 || v[0] != want {
			return cfg.ErrUnavailable
		}
	}
	for _, a := range g.attester.protection.plan.Administrators {
		if actorMatches(a, who.Status.UserInfo) {
			return cfg.ErrInvalid
		}
	}
	return nil
}

func (g *ConnectorAPIExecutionProtection) produceProof(ctx context.Context) (connectorAPIProof, error) {
	if g == nil || ctx == nil || ctx.Err() != nil {
		return connectorAPIProof{}, cfg.ErrUnavailable
	}
	start := g.attester.client.now()
	// Each failed check names itself and the elapsed share of the original
	// five seconds, for the regional process's diagnostic line.
	// The completed checks' marks profile where the five seconds went.
	var marks []string
	at := func(name string) string {
		return name + "@" + g.attester.client.now().Sub(start).Round(10*time.Millisecond).String()
	}
	mark := func(name string) { marks = append(marks, at(name)) }
	stage := func(name string, err error) error {
		return connectorAPIStage(at(name)+" after ["+strings.Join(marks, " ")+"]", err)
	}
	until := start.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
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
	if e = g.executionAccount(call, proof); e != nil {
		return connectorAPIProof{}, stage("execution-account", e)
	}
	mark("execution-account")
	digest, sourceUntil, e := g.settings.current(call)
	if e != nil {
		return connectorAPIProof{}, stage("settings-guard", e)
	}
	until = identity.Earlier(until, sourceUntil)
	call, c3 := context.WithDeadline(call, until)
	defer c3()
	mark("settings-guard")
	if e = g.snapshot(call); e != nil {
		return connectorAPIProof{}, stage("settings-snapshot", e)
	}
	mark("settings-snapshot")
	if e = g.workload(call, proof); e != nil {
		return connectorAPIProof{}, stage("workload", e)
	}
	mark("workload")
	last, finalUntil, e := g.settings.current(call)
	if e != nil || last != digest {
		return connectorAPIProof{}, stage("settings-guard-after", cfg.ErrChanged)
	}
	until = identity.Earlier(until, finalUntil)
	call, c4 := context.WithDeadline(call, until)
	defer c4()
	mark("settings-guard-after")
	if e = g.snapshot(call); e != nil {
		return connectorAPIProof{}, stage("settings-snapshot-after", e)
	}
	mark("settings-snapshot-after")
	finalProtection, protectionUntil, e := g.attester.protection.Current(call)
	if e != nil || finalProtection != proof.ProtectionDigest {
		return connectorAPIProof{}, stage("workload-guard-after", cfg.ErrChanged)
	}
	until = identity.Earlier(until, protectionUntil)
	call, c5 := context.WithDeadline(call, until)
	defer c5()
	mark("workload-guard-after")
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
	if call.Err() != nil || !identity.Fresh(start, until, g.attester.client.now(), 5*time.Second) || !proof.Valid(g.attester.client.now()) {
		return connectorAPIProof{}, stage("fresh", cfg.ErrUnavailable)
	}
	closed.Observation.Profile = closed.Observation.Profile.Clone()
	return connectorAPIProof{proof: proof.Clone(), owned: owned, source: closed, observedAt: start, validUntil: until}, nil
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
	// The enclosing observation owns its original five-second interval. The
	// guard starts later and must not return a deadline beyond CheckedAt + 5s.
	start := p.guard.attester.client.now()
	call, cancel := context.WithDeadline(ctx, start.Add(5*time.Second))
	defer cancel()
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
	if call.Err() != nil || p.parent.Err() != nil || !out.Valid(p.guard.attester.client.now()) {
		return zero, mtls.ConnectorProcessObservation{}, value.ErrUnavailable
	}
	owned := proof.owned
	owned.Request.ClientCSRDER = bytes.Clone(owned.Request.ClientCSRDER)
	owned.Request.ServerCSRDER = bytes.Clone(owned.Request.ServerCSRDER)
	owned.Configuration.Profile = owned.Configuration.Profile.Clone()
	owned.ValidUntil = identity.Earlier(owned.ValidUntil, until)
	return out, owned, nil
}
