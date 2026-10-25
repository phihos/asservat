package kubernetes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"maps"
	"reflect"
	"strings"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

// The first profile pins the API-returned, defaulted Deployment template. This
// normalizes ONLY three Pod-only scalar defaults plus the serviceAccount alias.
// Scheduler assignment is cleared only by the live-Pod comparison below.
// All token projections are explicit: automount=false permits no admission-added
// service-account volume/mount exception. Missing default tolerations are denied.
func connectorAPIPodSpec(s core.PodSpec) (core.PodSpec, error) {
	p := *s.DeepCopy()
	if p.AutomountServiceAccountToken == nil || *p.AutomountServiceAccountToken || p.ServiceAccountName == "" || p.HostNetwork || p.HostPID || p.HostIPC || len(p.Containers) != 1 || len(p.InitContainers) != 0 || len(p.EphemeralContainers) != 0 || len(p.SchedulingGates) != 0 || !restrictedAPIExecutionPod(p) || !digestPinnedAPIImage(p.Containers[0].Image) {
		return p, cfg.ErrInvalid
	}
	if p.RestartPolicy != core.RestartPolicyAlways || p.DNSPolicy == "" || p.SchedulerName == "" || p.TerminationGracePeriodSeconds == nil || p.Containers[0].ImagePullPolicy == "" || p.Containers[0].TerminationMessagePath == "" || p.Containers[0].TerminationMessagePolicy == "" {
		return p, cfg.ErrInvalid
	}
	if p.DeprecatedServiceAccount != "" && p.DeprecatedServiceAccount != p.ServiceAccountName {
		return p, cfg.ErrInvalid
	}
	p.DeprecatedServiceAccount = p.ServiceAccountName
	if p.EnableServiceLinks == nil {
		v := true
		p.EnableServiceLinks = &v
	}
	if p.PreemptionPolicy == nil {
		v := core.PreemptLowerPriority
		p.PreemptionPolicy = &v
	}
	if p.Priority == nil {
		v := int32(0)
		p.Priority = &v
	}
	// Both values must be explicit in the accepted template. Thus admission
	// cannot silently select another eviction interval or inject new tolerations.
	for _, key := range []string{"node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable"} {
		count := 0
		for _, t := range p.Tolerations {
			if t.Key == key {
				if t.Operator != core.TolerationOpExists || t.Value != "" || t.Effect != core.TaintEffectNoExecute || t.TolerationSeconds == nil || *t.TolerationSeconds != 300 {
					return p, cfg.ErrInvalid
				}
				count++
			}
		}
		if count != 1 {
			return p, cfg.ErrInvalid
		}
	}
	return p, nil
}

// ConnectorAPITemplateDigest keeps every Pod spec field, template annotation and
// label. The installer supplies a digest of the server-defaulted template under
// the independently protected source; a runtime observation cannot accept it.
func ConnectorAPITemplateDigest(t core.PodTemplateSpec) (artifact.Digest, error) {
	var zero artifact.Digest
	if t.Spec.NodeName != "" || len(t.OwnerReferences) != 0 || t.Name != "" || t.GenerateName != "" || t.Namespace != "" || t.UID != "" || t.ResourceVersion != "" || len(t.Finalizers) != 0 || len(t.ManagedFields) != 0 || t.DeletionTimestamp != nil || t.Labels[apps.DefaultDeploymentUniqueLabelKey] != "" {
		return zero, cfg.ErrInvalid
	}
	s, e := connectorAPIPodSpec(t.Spec)
	if e != nil {
		return zero, e
	}
	// Keep the full metadata rather than silently ignoring future fields.
	b, e := json.Marshal(core.PodTemplateSpec{ObjectMeta: *t.ObjectMeta.DeepCopy(), Spec: s})
	if e != nil || len(b) > 64<<10 {
		return zero, cfg.ErrInvalid
	}
	c := jsontext.Value(b)
	if c.Canonicalize() != nil {
		return zero, cfg.ErrInvalid
	}
	h := sha256.New()
	h.Write([]byte("asservat-connector-api-template/v1\x00"))
	h.Write(c)
	var d artifact.Digest
	copy(d[:], h.Sum(nil))
	return d, nil
}

// connectorAPITemplateMatch compares the live Deployment, ReplicaSet and Pod
// with the installed template and image digests. For a hub Deployment the
// caller passes the release record (ADR-227): each object is first mapped to
// its original-image view, so a Pod of the current or previous release image
// matches during and after a rollout. Connector callers pass nil (unchanged).
func connectorAPITemplateMatch(deployment *apps.Deployment, replica *apps.ReplicaSet, pod *core.Pod, expected, image artifact.Digest, release *contracts.ReleaseRecord, workload releaseWorkload) error {
	if deployment == nil || replica == nil || pod == nil || pod.Spec.NodeName == "" {
		return cfg.ErrChanged
	}
	if release != nil {
		d, e := releaseOriginal(*deployment, release, workload)
		if e != nil {
			return cfg.ErrChanged
		}
		r, p := releaseOriginalReplicaSet(*replica, release), releaseOriginalPod(*pod, release)
		deployment, replica, pod = &d, &r, &p
	}
	d, e := ConnectorAPITemplateDigest(deployment.Spec.Template)
	if e != nil || d != expected {
		return cfg.ErrChanged
	}
	r := replica.Spec.Template.DeepCopy()
	hash, ok := r.Labels[apps.DefaultDeploymentUniqueLabelKey]
	if !ok || len(hash) < 1 || len(hash) > 63 || pod.Labels[apps.DefaultDeploymentUniqueLabelKey] != hash || replica.Spec.Selector == nil || replica.Spec.Selector.MatchLabels[apps.DefaultDeploymentUniqueLabelKey] != hash {
		return cfg.ErrChanged
	}
	delete(r.Labels, apps.DefaultDeploymentUniqueLabelKey)
	d, e = ConnectorAPITemplateDigest(*r)
	if e != nil || d != expected {
		return cfg.ErrChanged
	}
	if !maps.Equal(pod.Labels, replica.Spec.Template.Labels) || !maps.Equal(pod.Annotations, replica.Spec.Template.Annotations) || len(pod.Finalizers) != 0 {
		return cfg.ErrChanged
	}
	live := pod.Spec.DeepCopy()
	live.NodeName = ""
	actual, e := connectorAPIPodSpec(*live)
	if e != nil {
		return cfg.ErrChanged
	}
	want, e := connectorAPIPodSpec(deployment.Spec.Template.Spec)
	if e != nil || !reflect.DeepEqual(actual, want) || !strings.HasSuffix(actual.Containers[0].Image, "@sha256:"+hex.EncodeToString(image[:])) {
		return cfg.ErrChanged
	}
	// Names, UIDs, selectors, controller refs and current phase are additionally
	// checked by the concrete ConnectorProcessAttester's exact live chain.
	return nil
}
