package kubernetes

import (
	"strings"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

// BuildInstalledOwnerWorkload fixes a zero-replica, identity-first owner before
// any object claim. Independent projection receipts and a one-use launch are
// still required. A mounted optional Secret never starts a backend by itself.
// The legacy builder and its serialized template remain unchanged.
func BuildInstalledOwnerWorkload(p OwnerWorkloadPlan) (*OwnerWorkload, error) {
	w, err := BuildOwnerWorkload(p)
	if err != nil {
		return nil, err
	}
	names := runtimeResourceNames(p.InstallationID)
	if p.Name != names.Owner || p.ServiceAccount != names.Owner || p.Configuration != names.OwnerInputs || p.Credentials != names.OwnerProviders || p.WorkloadGuard != names.WorkloadGuard {
		return nil, cfg.ErrInvalid
	}
	pod := &w.Deployment.Spec.Template.Spec
	// These two existing Kubernetes eviction bounds must be explicit in the
	// original template: the native matcher compares Deployment, ReplicaSet
	// and Pod without adopting Pod-admission additions as installation pins.
	pod.Tolerations = []core.Toleration{
		{Key: "node.kubernetes.io/not-ready", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))},
		{Key: "node.kubernetes.io/unreachable", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))},
	}
	// Observation startup has no worker routing dependency. Its own current
	// identity uses four separate SQL purposes and fixed provider credentials.
	pod.Volumes[0].Projected.Sources[0].ConfigMap.Items = []core.KeyToPath{{Key: "deployment.json", Path: "deployment.json"}}
	keys := append(contracts.OwnerIdentityProjectionFiles(), "audit-storage.json", "audit-wrap.token", "audit-unwrap.token", "owner-server-sign.token", "owner-client-sign.token")
	items := make([]core.KeyToPath, 0, len(keys))
	for _, key := range keys {
		items = append(items, core.KeyToPath{Key: key, Path: key})
	}
	pod.Volumes[0].Projected.Sources[1].Secret.Items = items
	// Each later projection has a separate fixed mount root. Its complete
	// immutable key set/content is checked against the independently accepted
	// original receipt before opening any credential or binding any route.
	pod.Volumes = append(pod.Volumes, core.Volume{Name: "observation", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: contracts.OwnerObservationProjectionName(p.InstallationID), Optional: ptr.To(true), DefaultMode: ptr.To(int32(0440))}}})
	pod.Containers[0].VolumeMounts = append(pod.Containers[0].VolumeMounts, core.VolumeMount{Name: "observation", MountPath: contracts.OwnerObservationProjectionRoot, ReadOnly: true})
	// ADR-184: the public root projects the immutable product role projection
	// and the operator's rotatable client secret and TLS Secret.
	pod.Volumes = append(pod.Volumes, core.Volume{Name: "public", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0440)), Sources: []core.VolumeProjection{
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: contracts.PublicRuntimeProjectionName(p.InstallationID)}, Optional: ptr.To(true)}},
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: contracts.OwnerPublicProjectionName(p.InstallationID)}, Optional: ptr.To(true)}},
	}}}})
	pod.Containers[0].VolumeMounts = append(pod.Containers[0].VolumeMounts, core.VolumeMount{Name: "public", MountPath: contracts.OwnerPublicProjectionRoot, ReadOnly: true})
	for _, port := range []struct {
		name   string
		number int32
	}{
		{"observation", contracts.OwnerInstalledNativePort},
		{"public", contracts.OwnerInstalledPublicPort},
	} {
		pod.Containers[0].Ports = append(pod.Containers[0].Ports, core.ContainerPort{Name: port.name, ContainerPort: port.number, Protocol: core.ProtocolTCP})
		w.Service.Spec.Ports = append(w.Service.Spec.Ports, core.ServicePort{Name: port.name, Port: port.number, TargetPort: intstr.FromInt32(port.number), Protocol: core.ProtocolTCP})
	}
	// ADR-197: the v2 operation listener. The hub-worker dials the holder's
	// Pod address and the region the L4 exposure, so the in-cluster Service
	// and its exact three-port endpoint set are unchanged.
	pod.Containers[0].Ports = append(pod.Containers[0].Ports, core.ContainerPort{Name: "operation", ContainerPort: contracts.OwnerInstalledOperationPort, Protocol: core.ProtocolTCP})
	// Named reads are limited to already-mounted fixed projections and public
	// provenance. No role-creation journal, broad Secret list or mutation is added.
	w.Role.Rules = append(w.Role.Rules, rbac.PolicyRule{
		APIGroups: []string{""}, Resources: []string{"secrets"},
		ResourceNames: []string{p.Credentials, "asservat-runtime-resources-" + strings.ReplaceAll(p.InstallationID, "-", ""), contracts.OwnerObservationProjectionName(p.InstallationID), contracts.OwnerPublicProjectionName(p.InstallationID), contracts.PublicRuntimeProjectionName(p.InstallationID)},
		Verbs:         []string{"get"},
	})
	w.Role.Rules = append(w.Role.Rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{p.Configuration}, Verbs: []string{"get"}})
	return w, nil
}
