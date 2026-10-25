package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *ConnectorObservationOperationReader) nativeBoundary(ctx context.Context, process value.ConnectorProcessIdentity, originalStart, until time.Time) (value.ConnectorObservationWorkload, error) {
	var zero value.ConnectorObservationWorkload
	if ctx.Err() != nil || !s.client.now().Before(until) {
		return zero, value.ErrUnavailable
	}
	// Distinct source and workload guards remain independently proved. This is
	// one real source guard observation, not a full source-value observation.
	sourceGuard, sourceUntil, err := s.source.protection.current(ctx)
	if err != nil || sourceGuard != s.pin.Profile.ProtectionDigest {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, sourceUntil)
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	g, p := s.guard, s.pin.Profile.Deployment
	ns, err := s.client.namespace(call, s.client.control)
	if err != nil || ns.Deleting {
		return zero, cfg.ErrChanged
	}
	guard, err := checkAdmissionGuard(call, s.client, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil {
		return zero, err
	}
	deployment, err := g.proveObject(call, originalStart)
	if err != nil {
		return zero, err
	}
	token, err := s.tokens.ReadConnectorPodToken(call)
	defer clear(token)
	if err != nil || len(token) < 1 || len(token) > 16<<10 || !bytes.Equal(bytes.TrimSpace(token), token) {
		return zero, value.ErrDenied
	}
	name, err := reviewBoundPodToken(call, s.client, token, ConnectorEnrollmentAudience(process.Binding.InstallationID), p.Namespace, p.ServiceAccount, p.AccountUID, process.PodUID)
	if err != nil {
		return zero, value.ErrDenied
	}
	expires, err := reviewedTokenExpiry(token, s.client.now())
	if err != nil {
		return zero, value.ErrDenied
	}
	until = identity.Earlier(until, expires)
	bounded, stop := context.WithDeadline(call, until)
	defer stop()
	reader := &OwnerEndpoints{client: s.client}
	base := "/api/v1/namespaces/" + p.Namespace + "/"
	account, err := ownerResource[core.ServiceAccount](reader, bounded, base+"serviceaccounts/"+p.ServiceAccount, "v1", "ServiceAccount")
	if err != nil || !ownerMetadata(account.ObjectMeta, p.Namespace, p.ServiceAccount, p.AccountUID) {
		return zero, value.ErrUnavailable
	}
	pod, err := ownerResource[core.Pod](reader, bounded, base+"pods/"+name, "v1", "Pod")
	if err != nil {
		return zero, err
	}
	ref, ok := ownerController(pod.OwnerReferences, "ReplicaSet", "apps/v1")
	if !ok {
		return zero, cfg.ErrChanged
	}
	replica, err := ownerResource[apps.ReplicaSet](reader, bounded, "/apis/apps/v1/namespaces/"+p.Namespace+"/replicasets/"+ref.Name, "apps/v1", "ReplicaSet")
	if err != nil {
		return zero, err
	}
	digest, err := s.nativeObjects(deployment, replica, pod, process, name)
	if err != nil {
		return zero, err
	}
	again, err := reviewBoundPodToken(bounded, s.client, token, ConnectorEnrollmentAudience(process.Binding.InstallationID), p.Namespace, p.ServiceAccount, p.AccountUID, process.PodUID)
	if err != nil || again != name {
		return zero, value.ErrDenied
	}
	last, err := ownerResource[core.Pod](reader, bounded, base+"pods/"+name, "v1", "Pod")
	if err != nil || last.ResourceVersion != pod.ResourceVersion || !equalJSON(last, pod) {
		return zero, cfg.ErrChanged
	}
	finalGuard, err := checkAdmissionGuard(bounded, s.client, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil || finalGuard != guard {
		return zero, cfg.ErrChanged
	}
	ns, err = s.client.namespace(bounded, s.client.control)
	out := value.ConnectorObservationWorkload{Process: process, Pod: name, ReplicaSetUID: string(replica.UID), TemplateDigest: s.pin.TemplateDigest, ImageDigest: s.pin.ImageDigest, ProtectionDigest: g.digest, WorkloadDigest: digest, ObservedAt: originalStart, FreshUntil: until}
	if err != nil || ns.Deleting || bounded.Err() != nil || !out.Matches(s.pin, s.client.now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}

func (s *ConnectorObservationOperationReader) nativeObjects(deployment apps.Deployment, replica apps.ReplicaSet, pod core.Pod, process value.ConnectorProcessIdentity, name string) (artifact.Digest, error) {
	var zero artifact.Digest
	p := s.pin.Profile.Deployment
	if !ownerMetadata(deployment.ObjectMeta, p.Namespace, p.Deployment, p.DeploymentUID) || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas < 1 || deployment.Spec.Template.Spec.ServiceAccountName != p.ServiceAccount || !ownerMetadata(pod.ObjectMeta, p.Namespace, name, process.PodUID) || pod.Spec.ServiceAccountName != p.ServiceAccount || pod.Spec.NodeName == "" || pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC || len(pod.Spec.EphemeralContainers) != 0 || pod.Status.Phase != core.PodPending && pod.Status.Phase != core.PodRunning || !ownerEnrollmentSelector(deployment.Spec.Selector, pod.Labels) {
		return zero, cfg.ErrChanged
	}
	ref, ok := ownerController(pod.OwnerReferences, "ReplicaSet", "apps/v1")
	if !ok || !ownerMetadata(replica.ObjectMeta, p.Namespace, ref.Name, string(ref.UID)) || replica.Spec.Replicas == nil || *replica.Spec.Replicas < 1 || !ownerEnrollmentSelector(replica.Spec.Selector, pod.Labels) {
		return zero, cfg.ErrChanged
	}
	parent, ok := ownerController(replica.OwnerReferences, "Deployment", "apps/v1")
	if !ok || parent.Name != p.Deployment || string(parent.UID) != p.DeploymentUID || connectorAPITemplateMatch(&deployment, &replica, &pod, s.pin.TemplateDigest, s.pin.ImageDigest, nil, 0) != nil {
		return zero, cfg.ErrChanged
	}
	raw, err := json.Marshal(struct {
		Pin                      value.ConnectorObservationPin
		Process                  value.ConnectorProcessIdentity
		Pod                      core.PodSpec
		Replica                  apps.ReplicaSetSpec
		Deployment               apps.DeploymentSpec
		Labels, Annotations      map[string]string
		PodOwners, ReplicaOwners []meta.OwnerReference
	}{s.pin, process, pod.Spec, replica.Spec, deployment.Spec, pod.Labels, pod.Annotations, pod.OwnerReferences, replica.OwnerReferences})
	if err != nil || len(raw) > 128<<10 {
		return zero, cfg.ErrInvalid
	}
	canonical := jsontext.Value(raw)
	if canonical.Canonicalize() != nil {
		return zero, cfg.ErrInvalid
	}
	h := sha256.New()
	h.Write([]byte("asservat-connector-observation-native-operation/v2\x00"))
	h.Write(canonical)
	copy(zero[:], h.Sum(nil))
	return zero, nil
}
