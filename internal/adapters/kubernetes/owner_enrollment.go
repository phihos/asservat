package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
)

// OwnerEnrollmentAttester observes the protected hub workload before Ready.
// Clean installation, durable registration and signing authority stay separate.
type OwnerEnrollmentAttester struct {
	client        *PermissionClient
	configuration app.OwnerConfigurationReader
	protection    *OwnerWorkloadProtection
	tokens        app.OwnerPodToken
}

var _ app.OwnerEnrollmentProofReader = (*OwnerEnrollmentAttester)(nil)

func NewOwnerEnrollmentAttester(c *PermissionClient, configurations app.OwnerConfigurationReader, protection *OwnerWorkloadProtection, tokens app.OwnerPodToken) (*OwnerEnrollmentAttester, error) {
	if c == nil || configurations == nil || protection == nil || protection.observer != c || tokens == nil {
		return nil, value.ErrInvalid
	}
	return &OwnerEnrollmentAttester{c, configurations, protection, tokens}, nil
}

func OwnerEnrollmentAudience(installation string) string {
	return "https://asservat." + installation + "/hub-owner-enrollment"
}

type ownerEnrollmentWorkload struct {
	Pod, ReplicaSet, ReplicaSetUID string
	Digest                         artifact.Digest
}

func ownerEnrollmentSelector(s *meta.LabelSelector, values map[string]string) bool {
	if s == nil || len(s.MatchLabels)+len(s.MatchExpressions) < 1 || len(s.MatchLabels)+len(s.MatchExpressions) > 32 {
		return false
	}
	selector, err := meta.LabelSelectorAsSelector(s)
	return err == nil && selector.Matches(labels.Set(values))
}

func (s *OwnerEnrollmentAttester) live(ctx context.Context, p value.OwnerPool, b value.OwnerBinding, name string) (out ownerEnrollmentWorkload, result error) {
	check := ownerReadLiveNamespaceRead
	defer ownerReadAnnotate(&check, &result)
	ns, err := s.client.namespace(ctx, s.client.control)
	if err != nil {
		return out, errors.Join(value.ErrUnavailable, err)
	}
	check = ownerReadLiveNamespaceContent
	if ns.Deleting {
		return out, value.ErrUnavailable
	}
	reader := &OwnerEndpoints{client: s.client, pool: p} // Resource reader only; never Ready endpoint discovery.
	check = ownerReadLiveAccountRead
	account, err := ownerResource[core.ServiceAccount](reader, ctx, "/api/v1/namespaces/"+p.Namespace+"/serviceaccounts/"+p.ServiceAccount, "v1", "ServiceAccount")
	if err != nil {
		return out, errors.Join(value.ErrUnavailable, err)
	}
	check = ownerReadLiveAccountContent
	if !ownerMetadata(account.ObjectMeta, p.Namespace, p.ServiceAccount, p.AccountUID) {
		return out, value.ErrUnavailable
	}
	check = ownerReadLiveDeploymentRead
	deployment, err := ownerResource[apps.Deployment](reader, ctx, "/apis/apps/v1/namespaces/"+p.Namespace+"/deployments/"+p.Deployment, "apps/v1", "Deployment")
	if err != nil {
		return out, errors.Join(value.ErrUnavailable, err)
	}
	check = ownerReadLiveDeploymentContent
	if !ownerMetadata(deployment.ObjectMeta, p.Namespace, p.Deployment, p.DeploymentUID) || deployment.Spec.Template.Spec.ServiceAccountName != p.ServiceAccount || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas < 1 {
		return out, value.ErrUnavailable
	}
	check = ownerReadLivePodRead
	pod, err := ownerResource[core.Pod](reader, ctx, "/api/v1/namespaces/"+p.Namespace+"/pods/"+name, "v1", "Pod")
	if err != nil {
		return out, errors.Join(value.ErrUnavailable, err)
	}
	check = ownerReadLivePodContent
	if !ownerMetadata(pod.ObjectMeta, p.Namespace, name, b.PodUID) || pod.Spec.ServiceAccountName != p.ServiceAccount || pod.Spec.NodeName == "" || pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC || len(pod.Spec.EphemeralContainers) != 0 || (pod.Status.Phase != core.PodPending && pod.Status.Phase != core.PodRunning) || !ownerEnrollmentSelector(deployment.Spec.Selector, pod.Labels) {
		return out, value.ErrUnavailable
	}
	ref, ok := ownerController(pod.OwnerReferences, "ReplicaSet", "apps/v1")
	if !ok {
		return out, value.ErrUnavailable
	}
	check = ownerReadLiveReplicaRead
	replica, err := ownerResource[apps.ReplicaSet](reader, ctx, "/apis/apps/v1/namespaces/"+p.Namespace+"/replicasets/"+ref.Name, "apps/v1", "ReplicaSet")
	if err != nil {
		return out, errors.Join(value.ErrUnavailable, err)
	}
	check = ownerReadLiveReplicaContent
	if !ownerMetadata(replica.ObjectMeta, p.Namespace, ref.Name, string(ref.UID)) || replica.Spec.Template.Spec.ServiceAccountName != p.ServiceAccount || replica.Spec.Replicas == nil || *replica.Spec.Replicas < 1 || !ownerEnrollmentSelector(replica.Spec.Selector, pod.Labels) {
		return out, value.ErrUnavailable
	}
	owner, ok := ownerController(replica.OwnerReferences, "Deployment", "apps/v1")
	if !ok || owner.Name != p.Deployment || string(owner.UID) != p.DeploymentUID {
		return out, value.ErrUnavailable
	}
	check = ownerReadLiveDigest
	// Status/RV-only changes during normal startup are allowed. Security-relevant
	// specs, selectors, labels and controller identities must remain identical.
	raw, err := json.Marshal(struct {
		Pool                     value.OwnerPool
		PodUID, ReplicaSetUID    string
		Pod                      core.PodSpec
		ReplicaSet               apps.ReplicaSetSpec
		Deployment               apps.DeploymentSpec
		Labels                   map[string]string
		PodOwners, ReplicaOwners []meta.OwnerReference
	}{p, b.PodUID, string(replica.UID), pod.Spec, replica.Spec, deployment.Spec, pod.Labels, pod.OwnerReferences, replica.OwnerReferences})
	defer clear(raw)
	if err != nil || len(raw) > 128<<10 {
		return out, value.ErrUnavailable
	}
	canonical := jsontext.Value(raw)
	if canonical.Canonicalize() != nil {
		return out, value.ErrUnavailable
	}
	defer clear(canonical)
	h := sha256.New()
	h.Write([]byte("asservat-owner-enrollment-workload/v1\x00"))
	h.Write(canonical)
	out = ownerEnrollmentWorkload{Pod: name, ReplicaSet: replica.Name, ReplicaSetUID: string(replica.UID)}
	copy(out.Digest[:], h.Sum(nil))
	return out, nil
}

func (s *OwnerEnrollmentAttester) ReadOwnerEnrollmentProof(ctx context.Context, r value.OwnerEnrollmentRequest) (value.OwnerEnrollmentProof, error) {
	var zero value.OwnerEnrollmentProof
	if s == nil || ctx == nil || s.client == nil || s.configuration == nil || s.protection == nil || s.tokens == nil || !r.Valid() {
		return zero, value.ErrInvalid
	}
	r.CSRDER = bytes.Clone(r.CSRDER)
	key, err := mtls.EnrollmentKey(r.CSRDER)
	if err != nil {
		return zero, value.ErrDenied
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start := s.client.now()
	first, err := s.configuration.ReadOwnerConfiguration(ctx)
	if err != nil || !first.Valid(s.client.now()) || first.Configuration.Suspended {
		return zero, fmt.Errorf("owner proof initial configuration: %w", value.ErrUnavailable)
	}
	first.Configuration = first.Configuration.Clone()
	p := first.Configuration.Pool
	b := r.Binding
	plan := s.protection.plan
	if b.InstallationID != p.InstallationID || b.ClusterID != p.ClusterID || b.IssuerEpoch != p.IssuerEpoch || p.ClusterID != s.client.clusterID || p.Namespace != s.client.control.Name || p.NamespaceUID != s.client.control.UID || p.Deployment != plan.Deployment || p.DeploymentUID != plan.DeploymentUID || len(validation.IsDNS1123Subdomain(p.ServiceAccount)) != 0 {
		return zero, value.ErrDenied
	}
	guard, guardUntil, err := s.protection.Current(ctx)
	if err != nil {
		return zero, fmt.Errorf("owner proof initial protection: %w", value.ErrUnavailable)
	}
	token, err := s.tokens.ReadOwnerPodToken(ctx)
	defer clear(token)
	if err != nil || len(token) < 1 || len(token) > 16<<10 || !bytes.Equal(bytes.TrimSpace(token), token) {
		return zero, value.ErrDenied
	}
	audience := OwnerEnrollmentAudience(p.InstallationID)
	name, err := reviewBoundPodToken(ctx, s.client, token, audience, p.Namespace, p.ServiceAccount, p.AccountUID, b.PodUID)
	if err != nil {
		return zero, value.ErrDenied
	}
	expires, err := reviewedTokenExpiry(token, s.client.now())
	if err != nil {
		return zero, value.ErrDenied
	}
	before, err := s.live(ctx, p, b, name)
	if err != nil {
		return zero, fmt.Errorf("owner proof initial workload: %w", value.ErrUnavailable)
	}
	again, err := reviewBoundPodToken(ctx, s.client, token, audience, p.Namespace, p.ServiceAccount, p.AccountUID, b.PodUID)
	if err != nil || again != name {
		return zero, value.ErrDenied
	}
	after, err := s.live(ctx, p, b, name)
	if err != nil || before != after {
		return zero, fmt.Errorf("owner proof repeated workload: %w", value.ErrUnavailable)
	}
	lastGuard, lastGuardUntil, err := s.protection.Current(ctx)
	if err != nil || lastGuard != guard {
		return zero, fmt.Errorf("owner proof final protection: %w", value.ErrUnavailable)
	}
	last, err := s.configuration.ReadOwnerConfiguration(ctx)
	if err != nil || !last.Valid(s.client.now()) || !last.Configuration.Equal(first.Configuration) || ctx.Err() != nil {
		return zero, fmt.Errorf("owner proof final configuration: %w", value.ErrUnavailable)
	}
	until := start.Add(5 * time.Second)
	for _, deadline := range []time.Time{first.FreshUntil, last.FreshUntil, guardUntil, lastGuardUntil, expires} {
		until = identity.Earlier(until, deadline)
	}
	out := value.OwnerEnrollmentProof{Binding: b, Usage: r.Usage, Configuration: first, Pod: name, ReplicaSet: before.ReplicaSet, ReplicaSetUID: before.ReplicaSetUID, PublicKeyDigest: key, TokenDigest: artifact.Digest(sha256.Sum256(token)), WorkloadDigest: before.Digest, ProtectionDigest: guard, ObservedAt: start, FreshUntil: until}
	if !out.Valid(s.client.now()) {
		return zero, fmt.Errorf("owner proof final freshness: %w", value.ErrUnavailable)
	}
	return out, nil
}
