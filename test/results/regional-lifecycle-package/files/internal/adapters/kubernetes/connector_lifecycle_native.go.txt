package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

func (o *connectorLifecycleOperation) configuration(data map[string]string, observed, until time.Time) (app.ConnectorIdentityConfiguration, time.Time, error) {
	s := o.reader
	c, rootsUntil, err := s.source.decodeConfiguration(data)
	until = identity.Earlier(until, identity.Earlier(rootsUntil, c.Backing.Policy.ValidUntil))
	c.Source.Observation.Profile.ProtectionDigest = s.source.protection.digest
	c.Source.Observation.ObservedAt, c.Source.Observation.FreshUntil = observed, until
	p := c.Source.Observation.Profile
	if err != nil || !c.Valid(s.client.now()) || p.Suspended || p.Retiring || p.Binding != o.request.Binding.Process.Binding ||
		p.Deployment.Namespace != s.client.control.Name || p.Deployment.NamespaceUID != s.client.control.UID ||
		p.Deployment.Deployment != s.guard.plan.Deployment || p.Deployment.DeploymentUID != s.guard.plan.DeploymentUID {
		return app.ConnectorIdentityConfiguration{}, until, value.ErrUnavailable
	}
	if o.first != nil && (o.first.Source.Roles != c.Source.Roles || !o.first.Source.Observation.SameSource(c.Source.Observation) || !connectorBackingEqual(*o.backing, c.Backing)) {
		return app.ConnectorIdentityConfiguration{}, until, cfg.ErrChanged
	}
	return c, until, nil
}

// sourceBoundary performs one independent denied source proof and retains the
// exact ConfigMap it submitted. Decoding that actual response does not create
// a second observation. A full value read still follows the complete boundary.
func (o *connectorLifecycleOperation) sourceBoundary(ctx context.Context, start, until time.Time) (app.ConnectorIdentityConfiguration, time.Time, error) {
	s, g := o.reader, o.reader.source.protection
	var zero app.ConnectorIdentityConfiguration
	ns, err := s.client.namespace(ctx, s.client.control)
	if err != nil || ns.Deleting {
		return zero, until, cfg.ErrChanged
	}
	before, err := checkAdmissionGuard(ctx, s.client, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil {
		return zero, until, err
	}
	cm, err := g.proveObject(ctx)
	if err != nil {
		return zero, until, err
	}
	after, err := checkAdmissionGuard(ctx, s.client, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil || after != before || s.client.current(ctx, start, 5*time.Second) != nil {
		return zero, until, cfg.ErrChanged
	}
	raw, err := json.Marshal(cm)
	if err != nil {
		return zero, until, cfg.ErrInvalid
	}
	data, _, err := s.client.decodeInstallationConfig(raw, s.source.name, s.source.uid, false)
	if err != nil {
		return zero, until, err
	}
	return o.configuration(data, start, until)
}

func (o *connectorLifecycleOperation) boundary(ctx context.Context, start, until time.Time) (value.ConnectorProcessProof, app.ConnectorIdentityConfiguration, time.Time, error) {
	var proof value.ConnectorProcessProof
	var zero app.ConnectorIdentityConfiguration
	s := o.reader
	first, until, err := o.sourceBoundary(ctx, start, until)
	if err != nil {
		return proof, zero, until, err
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	g, p := s.guard, first.Source.Observation.Profile.Deployment
	ns, err := s.client.namespace(call, s.client.control)
	if err != nil || ns.Deleting {
		return proof, zero, until, cfg.ErrChanged
	}
	guard, err := checkAdmissionGuard(call, s.client, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil {
		return proof, zero, until, err
	}
	deployment, err := g.proveObject(call, start)
	if err != nil {
		return proof, zero, until, err
	}
	name, expires, err := o.review(call, p)
	if err != nil {
		return proof, zero, until, err
	}
	until = identity.Earlier(until, expires)
	live, stop := context.WithDeadline(call, until)
	defer stop()
	work, _, replica, err := o.workload(live, p, name, &deployment)
	if err != nil {
		return proof, zero, until, err
	}
	again, expires, err := o.review(live, p)
	if err != nil || again != name {
		return proof, zero, until, value.ErrDenied
	}
	until = identity.Earlier(until, expires)
	lastCall, stopLast := context.WithDeadline(live, until)
	defer stopLast()
	reader := &OwnerEndpoints{client: s.client}
	last, err := ownerResource[core.Pod](reader, lastCall, "/api/v1/namespaces/"+p.Namespace+"/pods/"+name, "v1", "Pod")
	if err != nil {
		return proof, zero, until, err
	}
	lastWork, err := lifecycleWorkloadObjects(p, o.request.Binding.Process, name, deployment, replica, last)
	if err != nil || lastWork != work {
		return proof, zero, until, cfg.ErrChanged
	}
	finalGuard, err := checkAdmissionGuard(lastCall, s.client, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil || finalGuard != guard {
		return proof, zero, until, cfg.ErrChanged
	}
	ns, err = s.client.namespace(lastCall, s.client.control)
	if err != nil || ns.Deleting || s.client.current(lastCall, start, 5*time.Second) != nil {
		return proof, zero, until, cfg.ErrChanged
	}
	// Always read after both complete guards, including the final denied probe.
	// A change during its request cannot hide in the probe's earlier body.
	observed := s.client.now()
	data, _, err := s.client.installationConfig(lastCall, s.source.name, s.source.uid)
	if err != nil {
		return proof, zero, until, err
	}
	configuration, until, err := o.configuration(data, observed, until)
	if err != nil || first.Source.Roles != configuration.Source.Roles || !first.Source.Observation.SameSource(configuration.Source.Observation) || !connectorBackingEqual(first.Backing, configuration.Backing) || lastCall.Err() != nil {
		return proof, zero, until, cfg.ErrChanged
	}
	proof = o.proof(work, configuration.Source, start, until)
	if !proof.Valid(s.client.now()) {
		return value.ConnectorProcessProof{}, zero, until, value.ErrUnavailable
	}
	return proof, configuration, until, nil
}

// currentValues performs twelve actual native requests. It rechecks both exact
// policy/binding pairs, original token and complete live source/controller facts;
// it does not claim another denied probe or renew original native enforcement.
func (o *connectorLifecycleOperation) currentValues(ctx context.Context, start, until time.Time) (value.ConnectorProcessProof, app.ConnectorIdentityConfiguration, time.Time, error) {
	var proof value.ConnectorProcessProof
	var zero app.ConnectorIdentityConfiguration
	s := o.reader
	ns, err := s.client.namespace(ctx, s.client.control)
	if err != nil || ns.Deleting {
		return proof, zero, until, cfg.ErrChanged
	}
	sourceGuard := s.source.protection
	if _, err = checkAdmissionGuard(ctx, s.client, sourceGuard.plan.Name, sourceGuard.pin, sourceGuard.policy, sourceGuard.binding); err != nil {
		return proof, zero, until, err
	}
	g := s.guard
	if _, err = checkAdmissionGuard(ctx, s.client, g.plan.Name, g.pin, g.policy, g.binding); err != nil {
		return proof, zero, until, err
	}
	observed := s.client.now()
	raw, err := s.client.raw(ctx, "/api/v1/namespaces/"+s.client.control.Name+"/configmaps/"+s.source.name, nil)
	if err != nil {
		return proof, zero, until, err
	}
	data, _, err := s.client.decodeInstallationConfig(raw, s.source.name, s.source.uid, false)
	if err != nil {
		return proof, zero, until, err
	}
	configuration, until, err := o.configuration(data, observed, until)
	if err != nil {
		return proof, zero, until, err
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	p := configuration.Source.Observation.Profile.Deployment
	name, expires, err := o.review(call, p)
	if err != nil {
		return proof, zero, until, err
	}
	until = identity.Earlier(until, expires)
	live, stop := context.WithDeadline(call, until)
	defer stop()
	work, _, _, err := o.workload(live, p, name, nil)
	if err != nil {
		return proof, zero, until, err
	}
	ns, err = s.client.namespace(live, s.client.control)
	if err != nil || ns.Deleting || s.client.current(live, start, 5*time.Second) != nil {
		return proof, zero, until, cfg.ErrChanged
	}
	configuration.Source.Observation.FreshUntil = until
	proof = o.proof(work, configuration.Source, start, until)
	if !proof.Valid(s.client.now()) {
		return value.ConnectorProcessProof{}, zero, until, value.ErrUnavailable
	}
	return proof, configuration, until, nil
}

func (o *connectorLifecycleOperation) review(ctx context.Context, p value.ConnectorDeployment) (string, time.Time, error) {
	process, s := o.request.Binding.Process, o.reader
	name, err := reviewBoundPodToken(ctx, s.client, o.token, ConnectorEnrollmentAudience(process.Binding.InstallationID), p.Namespace, p.ServiceAccount, p.AccountUID, process.PodUID)
	if err != nil {
		return "", time.Time{}, value.ErrDenied
	}
	expires, err := reviewedTokenExpiry(o.token, s.client.now())
	if err != nil || ctx.Err() != nil {
		return "", time.Time{}, value.ErrDenied
	}
	return name, expires, nil
}

func (o *connectorLifecycleOperation) workload(ctx context.Context, p value.ConnectorDeployment, name string, actual *apps.Deployment) (ownerEnrollmentWorkload, core.Pod, apps.ReplicaSet, error) {
	var zero ownerEnrollmentWorkload
	var pod core.Pod
	var replica apps.ReplicaSet
	reader := &OwnerEndpoints{client: o.reader.client}
	account, err := ownerResource[core.ServiceAccount](reader, ctx, "/api/v1/namespaces/"+p.Namespace+"/serviceaccounts/"+p.ServiceAccount, "v1", "ServiceAccount")
	if err != nil || !ownerMetadata(account.ObjectMeta, p.Namespace, p.ServiceAccount, p.AccountUID) {
		return zero, pod, replica, value.ErrUnavailable
	}
	var deployment apps.Deployment
	if actual != nil {
		deployment = *actual
	} else {
		deployment, err = ownerResource[apps.Deployment](reader, ctx, "/apis/apps/v1/namespaces/"+p.Namespace+"/deployments/"+p.Deployment, "apps/v1", "Deployment")
		if err != nil {
			return zero, pod, replica, err
		}
	}
	pod, err = ownerResource[core.Pod](reader, ctx, "/api/v1/namespaces/"+p.Namespace+"/pods/"+name, "v1", "Pod")
	if err != nil {
		return zero, pod, replica, err
	}
	ref, ok := ownerController(pod.OwnerReferences, "ReplicaSet", "apps/v1")
	if !ok {
		return zero, pod, replica, cfg.ErrChanged
	}
	replica, err = ownerResource[apps.ReplicaSet](reader, ctx, "/apis/apps/v1/namespaces/"+p.Namespace+"/replicasets/"+ref.Name, "apps/v1", "ReplicaSet")
	if err != nil {
		return zero, pod, replica, err
	}
	w, err := lifecycleWorkloadObjects(p, o.request.Binding.Process, name, deployment, replica, pod)
	return w, pod, replica, err
}

func lifecycleWorkloadObjects(p value.ConnectorDeployment, process value.ConnectorProcessIdentity, name string, deployment apps.Deployment, replica apps.ReplicaSet, pod core.Pod) (ownerEnrollmentWorkload, error) {
	if !ownerMetadata(deployment.ObjectMeta, p.Namespace, p.Deployment, p.DeploymentUID) || deployment.Spec.Template.Spec.ServiceAccountName != p.ServiceAccount || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas < 1 ||
		!ownerMetadata(pod.ObjectMeta, p.Namespace, name, process.PodUID) || pod.Spec.ServiceAccountName != p.ServiceAccount || pod.Spec.NodeName == "" || pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC || len(pod.Spec.EphemeralContainers) != 0 ||
		pod.Status.Phase != core.PodPending && pod.Status.Phase != core.PodRunning || !ownerEnrollmentSelector(deployment.Spec.Selector, pod.Labels) {
		return ownerEnrollmentWorkload{}, cfg.ErrChanged
	}
	ref, ok := ownerController(pod.OwnerReferences, "ReplicaSet", "apps/v1")
	if !ok || !ownerMetadata(replica.ObjectMeta, p.Namespace, ref.Name, string(ref.UID)) || replica.Spec.Template.Spec.ServiceAccountName != p.ServiceAccount || replica.Spec.Replicas == nil || *replica.Spec.Replicas < 1 || !ownerEnrollmentSelector(replica.Spec.Selector, pod.Labels) {
		return ownerEnrollmentWorkload{}, cfg.ErrChanged
	}
	parent, ok := ownerController(replica.OwnerReferences, "Deployment", "apps/v1")
	if !ok || parent.Name != p.Deployment || string(parent.UID) != p.DeploymentUID {
		return ownerEnrollmentWorkload{}, cfg.ErrChanged
	}
	return connectorProcessWorkload(p, process, name, deployment, replica, pod)
}
