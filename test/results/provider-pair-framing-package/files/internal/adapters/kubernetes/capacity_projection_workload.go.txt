package kubernetes

import (
	"context"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	coordination "k8s.io/api/coordination/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *InstalledWorkerProjectionReader) checkedWorkerDeployment(ctx context.Context, state contracts.InitialRuntimeResourceState) (*apps.Deployment, *HubWorkerWorkload, error) {
	a := s.input.Activation
	var d apps.Deployment
	if e := s.get(ctx, "/apis/apps/v1/namespaces/"+s.input.Namespace.Name+"/deployments/"+a.Deployment.Name, &d); e != nil {
		return nil, nil, e
	}
	if d.APIVersion != "apps/v1" || d.Kind != "Deployment" || !ownerMetadata(d.ObjectMeta, s.input.Namespace.Name, a.Deployment.Name, a.Deployment.UID) ||
		len(d.Spec.Template.Spec.Containers) != 1 || d.Spec.Replicas == nil || *d.Spec.Replicas != 1 || d.Generation != state.Objects[11].Receipt.Generation+1 ||
		d.Annotations[initialRuntimeResourceMarker] != state.Objects[11].OperationID || !authorization.UUID(d.Annotations[configurationLaunchAnnotation]) {
		return nil, nil, cfg.ErrChanged
	}
	count := 2
	if revision, ok := d.Annotations["deployment.kubernetes.io/revision"]; ok {
		if revision != "1" {
			return nil, nil, cfg.ErrChanged
		}
		count++
	}
	if len(d.Annotations) != count {
		return nil, nil, cfg.ErrChanged
	}
	n := runtimeResourceNames(s.input.InstallationID)
	plan := HubWorkerWorkloadPlan{Namespace: s.input.Namespace.Name, Name: n.Worker, ServiceAccount: n.Worker, Configuration: n.WorkerInputs, Credentials: n.WorkerProviders, Image: d.Spec.Template.Spec.Containers[0].Image, FleetSource: s.input.FleetSource.Name, OwnerSource: n.OwnerSource, FleetGuard: s.input.FleetGuard.Name, OwnerGuard: n.OwnerSourceGuard, LeaderLease: n.Lease}
	want, e := BuildInstalledHubWorkerWorkload(plan, s.input.InstallationID)
	if a.WorkerLayout == contracts.HubWorkerProviderInstalledLayout {
		if state.WorkerProvider == nil || s.input.ProviderAuthentication == nil {
			return nil, nil, cfg.ErrChanged
		}
		want, e = BuildProviderHubWorkerWorkload(plan, s.input.InstallationID, s.input.ClusterID, *state.WorkerProvider)
		if e == nil {
			e = s.currentProviderInput(ctx, state)
		}
	} else if state.WorkerProvider != nil || state.WorkerInputs != nil {
		return nil, nil, cfg.ErrChanged
	}
	if e != nil {
		return nil, nil, e
	}
	if preparationDigest(want.Deployment) != state.Objects[11].TemplateDigest || preparationDigest(want.Account) != state.Objects[1].TemplateDigest {
		return nil, nil, cfg.ErrChanged
	}
	copy := d.DeepCopy()
	*copy.Spec.Replicas = 0
	copy.Annotations = nil
	if normalizeInitialRuntimeObject(copy) != nil || normalizeInitialRuntimeObject(want.Deployment) != nil || !equalJSON(copy, want.Deployment) {
		return nil, nil, cfg.ErrChanged
	}
	return &d, want, nil
}

func (s *InstalledWorkerProjectionReader) workload(ctx context.Context, state contracts.InitialRuntimeResourceState) error {
	_, want, e := s.checkedWorkerDeployment(ctx, state)
	if e != nil {
		return e
	}
	a := s.input.Activation
	original := func(index int, ref contracts.WorkerObjectReference) contracts.PublicRuntimeWorkerObject {
		c := state.Objects[index]
		return contracts.PublicRuntimeWorkerObject{Reference: ref, OperationID: c.OperationID, TemplateDigest: c.TemplateDigest}
	}
	var account core.ServiceAccount
	if e = s.get(ctx, "/api/v1/namespaces/"+s.input.Namespace.Name+"/serviceaccounts/"+a.ServiceAccount.Name, &account); e != nil {
		return e
	}
	if e = workerOriginalObject(&account, want.Account, original(1, a.ServiceAccount), s.input.Namespace.Name); e != nil {
		return e
	}
	var lease coordination.Lease
	if e = s.get(ctx, "/apis/coordination.k8s.io/v1/namespaces/"+s.input.Namespace.Name+"/leases/"+s.input.LeaderLease.Name, &lease); e != nil {
		return e
	}
	lease.Spec = coordination.LeaseSpec{}
	wantLease := &coordination.Lease{TypeMeta: meta.TypeMeta{APIVersion: "coordination.k8s.io/v1", Kind: "Lease"}, ObjectMeta: meta.ObjectMeta{Name: s.input.LeaderLease.Name, Namespace: s.input.Namespace.Name}}
	if preparationDigest(wantLease) != state.Objects[13].TemplateDigest {
		return cfg.ErrChanged
	}
	return workerOriginalObject(&lease, wantLease, original(13, s.input.LeaderLease), s.input.Namespace.Name)
}

func (s *InstalledWorkerProjectionReader) projectionMetadata(ctx context.Context, setupID, operationID, publicDigest string, secret contracts.WorkerObjectReference, resourceVersion string) error {
	raw, e := s.client.api.Get().AbsPath("/api/v1/namespaces/"+s.input.Namespace.Name+"/secrets/"+secret.Name).
		SetHeader("Accept", "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1").MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	var object meta.PartialObjectMetadata
	if e != nil {
		return cfg.ErrUnavailable
	}
	if permissionJSON(raw, 32<<10, 4096) != nil || strictGuardJSON(raw, &object) != nil || object.APIVersion != "meta.k8s.io/v1" || object.Kind != "PartialObjectMetadata" ||
		!ownerMetadata(object.ObjectMeta, s.input.Namespace.Name, secret.Name, secret.UID) || object.ResourceVersion != resourceVersion ||
		len(object.OwnerReferences) != 0 || len(object.Finalizers) != 0 || len(object.Labels) != 0 ||
		!equalJSON(object.Annotations, capacityProjectionAnnotations(s.input.Activation.Resources.UID, setupID, &contracts.CapacityRuntimeProjectionClaim{OperationID: operationID, PublicDigest: publicDigest})) {
		return cfg.ErrChanged
	}
	until, ok := ctx.Deadline()
	if !ok {
		return cfg.ErrInvalid
	}
	return initialHandoverDeadline(ctx, s.client.now, until)
}
