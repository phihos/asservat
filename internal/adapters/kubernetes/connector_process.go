package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConnectorProcessAttester reuses the concrete private namespace admission
// guard and bounded Kubernetes resource/token readers. It never constructs an
// OwnerBinding or treats Pod proof as process-registration/signing authority.
type ConnectorProcessAttester struct {
	client     *PermissionClient
	source     app.ConnectorIdentitySourceReader
	protection *OwnerWorkloadProtection
	tokens     app.ConnectorPodToken
}

var _ app.ConnectorProcessProofReader = (*ConnectorProcessAttester)(nil)

func NewConnectorProcessAttester(c *PermissionClient, source app.ConnectorIdentitySourceReader, protection *OwnerWorkloadProtection, tokens app.ConnectorPodToken) (*ConnectorProcessAttester, error) {
	if c == nil || source == nil || protection == nil || protection.observer != c || tokens == nil {
		return nil, value.ErrInvalid
	}
	return &ConnectorProcessAttester{c, source, protection, tokens}, nil
}
func ConnectorEnrollmentAudience(installation string) string {
	return "https://asservat." + installation + "/connector-process-enrollment"
}
func (s *ConnectorProcessAttester) live(ctx context.Context, p value.ConnectorDeployment, b value.ConnectorProcessIdentity, name string) (ownerEnrollmentWorkload, error) {
	var out ownerEnrollmentWorkload
	ns, err := s.client.namespace(ctx, s.client.control)
	if err != nil || ns.Deleting {
		return out, value.ErrUnavailable
	}
	reader := &OwnerEndpoints{client: s.client} // Resource reader only; never Ready endpoint discovery.
	account, err := ownerResource[core.ServiceAccount](reader, ctx, "/api/v1/namespaces/"+p.Namespace+"/serviceaccounts/"+p.ServiceAccount, "v1", "ServiceAccount")
	if err != nil || !ownerMetadata(account.ObjectMeta, p.Namespace, p.ServiceAccount, p.AccountUID) {
		return out, value.ErrUnavailable
	}
	deployment, err := ownerResource[apps.Deployment](reader, ctx, "/apis/apps/v1/namespaces/"+p.Namespace+"/deployments/"+p.Deployment, "apps/v1", "Deployment")
	if err != nil || !ownerMetadata(deployment.ObjectMeta, p.Namespace, p.Deployment, p.DeploymentUID) || deployment.Spec.Template.Spec.ServiceAccountName != p.ServiceAccount || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas < 1 {
		return out, value.ErrUnavailable
	}
	pod, err := ownerResource[core.Pod](reader, ctx, "/api/v1/namespaces/"+p.Namespace+"/pods/"+name, "v1", "Pod")
	if err != nil || !ownerMetadata(pod.ObjectMeta, p.Namespace, name, b.PodUID) || pod.Spec.ServiceAccountName != p.ServiceAccount || pod.Spec.NodeName == "" || pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC || len(pod.Spec.EphemeralContainers) != 0 || (pod.Status.Phase != core.PodPending && pod.Status.Phase != core.PodRunning) || !ownerEnrollmentSelector(deployment.Spec.Selector, pod.Labels) {
		return out, value.ErrUnavailable
	}
	ref, ok := ownerController(pod.OwnerReferences, "ReplicaSet", "apps/v1")
	if !ok {
		return out, value.ErrUnavailable
	}
	replica, err := ownerResource[apps.ReplicaSet](reader, ctx, "/apis/apps/v1/namespaces/"+p.Namespace+"/replicasets/"+ref.Name, "apps/v1", "ReplicaSet")
	if err != nil || !ownerMetadata(replica.ObjectMeta, p.Namespace, ref.Name, string(ref.UID)) || replica.Spec.Template.Spec.ServiceAccountName != p.ServiceAccount || replica.Spec.Replicas == nil || *replica.Spec.Replicas < 1 || !ownerEnrollmentSelector(replica.Spec.Selector, pod.Labels) {
		return out, value.ErrUnavailable
	}
	owner, ok := ownerController(replica.OwnerReferences, "Deployment", "apps/v1")
	if !ok || owner.Name != p.Deployment || string(owner.UID) != p.DeploymentUID {
		return out, value.ErrUnavailable
	}
	return connectorProcessWorkload(p, b, name, deployment, replica, pod)
}

func connectorProcessWorkload(p value.ConnectorDeployment, b value.ConnectorProcessIdentity, name string, deployment apps.Deployment, replica apps.ReplicaSet, pod core.Pod) (ownerEnrollmentWorkload, error) {
	// Status/RV-only changes during normal startup are allowed. Security-relevant
	// specs, selectors, labels and controller identities must remain identical.
	raw, err := json.Marshal(struct {
		DeploymentPin            value.ConnectorDeployment
		PodUID, ReplicaSetUID    string
		Pod                      core.PodSpec
		ReplicaSet               apps.ReplicaSetSpec
		Deployment               apps.DeploymentSpec
		Labels                   map[string]string
		PodOwners, ReplicaOwners []meta.OwnerReference
	}{p, b.PodUID, string(replica.UID), pod.Spec, replica.Spec, deployment.Spec, pod.Labels, pod.OwnerReferences, replica.OwnerReferences})
	defer clear(raw)
	if err != nil || len(raw) > 128<<10 {
		return ownerEnrollmentWorkload{}, value.ErrUnavailable
	}
	canonical := jsontext.Value(raw)
	if canonical.Canonicalize() != nil {
		return ownerEnrollmentWorkload{}, value.ErrUnavailable
	}
	defer clear(canonical)
	h := sha256.New()
	h.Write([]byte("asservat-connector-process-workload/v1\x00"))
	h.Write(canonical)
	out := ownerEnrollmentWorkload{Pod: name, ReplicaSet: replica.Name, ReplicaSetUID: string(replica.UID)}
	copy(out.Digest[:], h.Sum(nil))
	return out, nil
}

func (s *ConnectorProcessAttester) ReadConnectorProcessProof(ctx context.Context, r value.ConnectorProcessRequest) (value.ConnectorProcessProof, error) {
	return s.readConnectorProcessAttestation(ctx, r, false)
}

// ReadConnectorProcessProofAt attests the process against one source
// observation its caller read within the same original interval (ADR-199);
// it reads the source no further. The caller brackets the source itself.
func (s *ConnectorProcessAttester) ReadConnectorProcessProofAt(ctx context.Context, r value.ConnectorProcessRequest, source value.ConnectorIdentitySource) (value.ConnectorProcessProof, error) {
	if s == nil {
		return value.ConnectorProcessProof{}, value.ErrInvalid
	}
	proof, _, err := s.readConnectorProcessSourceAttestationWith(ctx, r, false, func(context.Context) (value.ConnectorIdentitySource, error) {
		out := source
		out.Observation.Profile = out.Observation.Profile.Clone()
		return out, nil
	})
	return proof, err
}

// The purpose switch is private. Each exported method returns a distinct proof
// type; ordinary proof validation never accepts a retiring source.
func (s *ConnectorProcessAttester) readConnectorProcessAttestation(ctx context.Context, r value.ConnectorProcessRequest, retirement bool) (value.ConnectorProcessProof, error) {
	proof, _, err := s.readConnectorProcessSourceAttestation(ctx, r, retirement)
	return proof, err
}

// The observation conversation also needs the exact full source already read by
// this attestation. Returning it adds no I/O, acceptance or freshness interval.
func (s *ConnectorProcessAttester) readConnectorProcessSourceAttestation(ctx context.Context, r value.ConnectorProcessRequest, retirement bool) (value.ConnectorProcessProof, value.ConnectorIdentitySource, error) {
	if s == nil {
		return value.ConnectorProcessProof{}, value.ConnectorIdentitySource{}, value.ErrInvalid
	}
	return s.readConnectorProcessSourceAttestationWith(ctx, r, retirement, s.source.ReadConnectorIdentitySource)
}

func (s *ConnectorProcessAttester) readConnectorProcessSourceAttestationWith(ctx context.Context, r value.ConnectorProcessRequest, retirement bool, read func(context.Context) (value.ConnectorIdentitySource, error)) (value.ConnectorProcessProof, value.ConnectorIdentitySource, error) {
	var zero value.ConnectorProcessProof
	var noSource value.ConnectorIdentitySource
	if s == nil || ctx == nil || !r.Valid() || read == nil {
		return zero, noSource, value.ErrInvalid
	}
	r.ClientCSRDER = bytes.Clone(r.ClientCSRDER)
	r.ServerCSRDER = bytes.Clone(r.ServerCSRDER)
	clientKey, e := mtls.EnrollmentKey(r.ClientCSRDER)
	if e != nil {
		return zero, noSource, value.ErrDenied
	}
	serverKey, e := mtls.EnrollmentKey(r.ServerCSRDER)
	if e != nil || serverKey == clientKey {
		return zero, noSource, value.ErrDenied
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start := s.client.now()
	first, e := read(ctx)
	if e != nil || !first.Valid(s.client.now()) || !connectorAttestationPurpose(first.Observation.Profile, retirement) {
		return zero, noSource, connectorAPIStage("attest-source", value.ErrUnavailable)
	}
	first.Observation.Profile = first.Observation.Profile.Clone()
	p := first.Observation.Profile.Deployment
	b := r.Process
	plan := s.protection.plan
	if b.Binding != first.Observation.Profile.Binding || b.Binding.ClusterID != s.client.clusterID || p.Namespace != s.client.control.Name || p.NamespaceUID != s.client.control.UID || p.Deployment != plan.Deployment || p.DeploymentUID != plan.DeploymentUID {
		return zero, noSource, connectorAPIStage("attest-binding", value.ErrDenied)
	}
	guard, guardUntil, e := s.protection.Current(ctx)
	if e != nil {
		return zero, noSource, connectorAPIStage("attest-workload-guard", errors.Join(value.ErrUnavailable, e))
	}
	token, e := s.tokens.ReadConnectorPodToken(ctx)
	defer clear(token)
	if e != nil || len(token) < 1 || len(token) > 16<<10 || !bytes.Equal(bytes.TrimSpace(token), token) {
		return zero, noSource, connectorAPIStage("attest-pod-token", value.ErrDenied)
	}
	audience := ConnectorEnrollmentAudience(b.Binding.InstallationID)
	name, e := reviewBoundPodToken(ctx, s.client, token, audience, p.Namespace, p.ServiceAccount, p.AccountUID, b.PodUID)
	if e != nil {
		return zero, noSource, connectorAPIStage("attest-token-review", value.ErrDenied)
	}
	expires, e := reviewedTokenExpiry(token, s.client.now())
	if e != nil {
		return zero, noSource, connectorAPIStage("attest-token-expiry", value.ErrDenied)
	}
	before, e := s.live(ctx, p, b, name)
	if e != nil {
		return zero, noSource, connectorAPIStage("attest-live", value.ErrUnavailable)
	}
	again, e := reviewBoundPodToken(ctx, s.client, token, audience, p.Namespace, p.ServiceAccount, p.AccountUID, b.PodUID)
	if e != nil || again != name {
		return zero, noSource, connectorAPIStage("attest-token-review-after", value.ErrDenied)
	}
	after, e := s.live(ctx, p, b, name)
	if e != nil || before != after {
		return zero, noSource, connectorAPIStage("attest-live-after", value.ErrUnavailable)
	}
	finalGuard, finalUntil, e := s.protection.Current(ctx)
	if e != nil || finalGuard != guard {
		return zero, noSource, connectorAPIStage("attest-workload-guard-after", value.ErrUnavailable)
	}
	last, e := read(ctx)
	if e != nil || !last.Valid(s.client.now()) || last.Roles != first.Roles || !last.Observation.SameSource(first.Observation) || ctx.Err() != nil {
		return zero, noSource, connectorAPIStage("attest-source-after", value.ErrUnavailable)
	}
	until := start.Add(5 * time.Second)
	if deadline, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, deadline)
	}
	for _, bound := range []time.Time{first.Observation.FreshUntil, last.Observation.FreshUntil, guardUntil, finalUntil, expires} {
		until = identity.Earlier(until, bound)
	}
	out := value.ConnectorProcessProof{Process: b, Configuration: first.Observation, Pod: name, ReplicaSet: before.ReplicaSet, ReplicaSetUID: before.ReplicaSetUID, ClientKeyDigest: clientKey, ServerKeyDigest: serverKey, TokenDigest: artifact.Digest(sha256.Sum256(token)), WorkloadDigest: before.Digest, ProtectionDigest: guard, ObservedAt: start, FreshUntil: until}
	valid := out.Valid(s.client.now())
	if retirement {
		valid = value.ConnectorRetirementProof(out).Valid(s.client.now())
	}
	if !valid || ctx.Err() != nil {
		return zero, noSource, connectorAPIStage("attest-valid", value.ErrUnavailable)
	}
	return out, first, nil
}

func connectorAttestationPurpose(p value.ConnectorCredentialProfile, retirement bool) bool {
	if retirement {
		return p.Suspended && p.Retiring
	}
	return !p.Suspended && !p.Retiring
}
