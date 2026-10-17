package kubernetes

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	coordination "k8s.io/api/coordination/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Complete actual values within one worker-provider native bracket. These
// private fields never implement a reader or establish a replacement interval.
type configurationProviderNative struct {
	until           time.Time
	guards          [3]string
	resources       contracts.InitialRuntimeResourceState
	fleet           fleet.Administration
	owner           fleet.OwnerConfiguration
	fleetRef        cfg.Resource
	ownerRef        cfg.Resource
	deployment      apps.Deployment
	ownerDeployment apps.Deployment
	account         core.ServiceAccount
	process         configurationProviderProcess
	podName         string
}

func (s *ConfigurationWorkerProviderReader) providerGuardVersions(ctx context.Context) ([3]string, error) {
	var out [3]string
	w := s.worker.guard
	v, err := checkAdmissionGuard(ctx, s.worker.client, w.plan.Name, w.pin, w.policy, w.binding)
	if err != nil {
		return out, err
	}
	out[0] = v
	for i, g := range []*configMapProtection{s.fleet.protection.configMapProtection, s.owner.protection.configMapProtection} {
		out[i+1], err = checkAdmissionGuard(ctx, s.worker.client, g.plan.Name, g.pin, g.policy, g.binding)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// Each phase reads twenty actual observer values. Initial independently proves
// all three denied operations (nine probe requests); final reuses only those
// original intervals and rereads every mutable value. This is the explicit
// whole-operation ADR148 boundary, not nested Current calls or a proof cache.
func (s *ConfigurationWorkerProviderReader) readConfigurationProviderNative(ctx context.Context, started time.Time, epoch string, manifest contracts.ConfigurationRuntimeCredentialManifest, mounted map[string][]byte, initial bool) (configurationProviderNative, error) {
	var out configurationProviderNative
	if !s.providerClientsBound() || ctx == nil || ctx.Err() != nil {
		return out, cfg.ErrUnavailable
	}
	w := s.worker
	call, end := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer end()
	until, _ := call.Deadline()
	var err error
	if initial {
		ns, e := w.client.namespace(call, w.client.control)
		if e != nil {
			return out, e
		}
		if ns.Deleting {
			return out, cfg.ErrChanged
		}
	}
	out.guards, err = s.providerGuardVersions(call)
	if err != nil {
		return out, err
	}
	var sources [2]core.ConfigMap
	var actors [3]auth.UserInfo
	if initial {
		probeCall, stop := context.WithCancel(call)
		var joined sync.WaitGroup
		var failures [3]error
		joined.Add(3)
		go func() {
			defer joined.Done()
			out.ownerDeployment, actors[0], failures[0] = w.guard.proveObjectIdentity(probeCall, started)
			if failures[0] != nil {
				stop()
			}
		}()
		go func() {
			defer joined.Done()
			sources[0], actors[1], failures[1] = s.fleet.protection.proveObjectIdentity(probeCall)
			if failures[1] != nil {
				stop()
			}
		}()
		go func() {
			defer joined.Done()
			sources[1], actors[2], failures[2] = s.owner.protection.proveObjectIdentity(probeCall)
			if failures[2] != nil {
				stop()
			}
		}()
		joined.Wait()
		stop()
		for _, e := range failures {
			if e != nil {
				return out, e
			}
		}
	} else {
		g := w.guard.plan
		if err = w.get(call, "/apis/apps/v1/namespaces/"+g.ControlNamespace.Name+"/deployments/"+g.Deployment, &out.ownerDeployment); err != nil {
			return out, err
		}
		if out.ownerDeployment.APIVersion != "apps/v1" || out.ownerDeployment.Kind != "Deployment" || !ownerMetadata(out.ownerDeployment.ObjectMeta, g.ControlNamespace.Name, g.Deployment, g.DeploymentUID) {
			return out, cfg.ErrChanged
		}
		for i, ref := range []contracts.WorkerObjectReference{w.input.FleetSource, w.input.OwnerSource} {
			if err = w.get(call, "/api/v1/namespaces/"+w.input.Namespace.Name+"/configmaps/"+ref.Name, &sources[i]); err != nil {
				return out, err
			}
		}
	}
	out.fleet, out.owner, out.fleetRef, out.ownerRef, out.until, err = s.providerSourceValues(sources, started, epoch)
	if err != nil {
		return out, err
	}
	until = identity.Earlier(until, out.until)
	call, narrow := context.WithDeadline(call, until)
	defer narrow()
	out.podName, err = w.configurationProviderIdentity(call, s.podUID)
	if err != nil {
		return out, err
	}
	if initial {
		for _, actor := range actors {
			name, e := w.configurationProviderActor(actor, s.podUID)
			if e != nil || name != out.podName {
				return out, cfg.ErrDenied
			}
		}
	}
	out.resources, err = w.journal(call)
	if err != nil {
		return out, err
	}
	deployment, want, err := w.checkedWorkerDeployment(call, out.resources)
	if err != nil {
		return out, err
	}
	out.deployment = *deployment.DeepCopy()
	original := func(index int, ref contracts.WorkerObjectReference) contracts.PublicRuntimeWorkerObject {
		claim := out.resources.Objects[index]
		return contracts.PublicRuntimeWorkerObject{Reference: ref, OperationID: claim.OperationID, TemplateDigest: claim.TemplateDigest}
	}
	a := w.input.Activation
	if err = w.get(call, "/api/v1/namespaces/"+w.input.Namespace.Name+"/serviceaccounts/"+a.ServiceAccount.Name, &out.account); err != nil {
		return out, err
	}
	if err = workerOriginalObject(&out.account, want.Account, original(1, a.ServiceAccount), w.input.Namespace.Name); err != nil {
		return out, err
	}
	var lease coordination.Lease
	if err = w.get(call, "/apis/coordination.k8s.io/v1/namespaces/"+w.input.Namespace.Name+"/leases/"+w.input.LeaderLease.Name, &lease); err != nil {
		return out, err
	}
	lease.Spec = coordination.LeaseSpec{} // scheduling state is not authority
	wantLease := &coordination.Lease{TypeMeta: meta.TypeMeta{APIVersion: "coordination.k8s.io/v1", Kind: "Lease"}, ObjectMeta: meta.ObjectMeta{Name: w.input.LeaderLease.Name, Namespace: w.input.Namespace.Name}}
	if preparationDigest(wantLease) != out.resources.Objects[13].TemplateDigest {
		return out, cfg.ErrChanged
	}
	if err = workerOriginalObject(&lease, wantLease, original(13, w.input.LeaderLease), w.input.Namespace.Name); err != nil {
		return out, err
	}
	out.process, err = w.configurationProviderProcessDeployment(call, deployment, out.podName, s.podUID)
	if err != nil {
		return out, err
	}
	if err = w.configurationProviderProjection(call, manifest, mounted); err != nil {
		return out, err
	}
	if !initial {
		ns, e := w.client.namespace(call, w.client.control)
		if e != nil {
			return out, e
		}
		if ns.Deleting {
			return out, cfg.ErrChanged
		}
	}
	if initialHandoverDeadline(call, w.client.now, until) != nil || !out.fleet.Valid(w.client.now()) {
		return out, cfg.ErrUnavailable
	}
	out.until = until
	return out, nil
}

// The supplied ConfigMaps are complete actual probe/final GET values. Decoding
// uses the same closed source validators and original operation start; it does
// not call a protected reader or manufacture a later observation date.
func (s *ConfigurationWorkerProviderReader) providerSourceValues(objects [2]core.ConfigMap, started time.Time, epoch string) (fleet.Administration, fleet.OwnerConfiguration, cfg.Resource, cfg.Resource, time.Time, error) {
	var f fleet.Administration
	var o fleet.OwnerConfiguration
	var fr, or cfg.Resource
	var until time.Time
	in, client := s.worker.input, s.worker.client
	raw, err := json.Marshal(objects[0])
	if err != nil {
		return f, o, fr, or, until, cfg.ErrChanged
	}
	data, fr, err := client.decodeInstallationConfig(raw, in.FleetSource.Name, in.FleetSource.UID, false)
	if err != nil {
		return f, o, fr, or, until, err
	}
	f, err = s.fleet.settings.decodeFleetAdministration(data, fr, started)
	if err != nil || !f.Valid(client.now()) || f.Suspended || f.IssuerEpoch != epoch {
		return f, o, fr, or, until, cfg.ErrUnavailable
	}
	raw, err = json.Marshal(objects[1])
	if err != nil {
		return f, o, fr, or, until, cfg.ErrChanged
	}
	data, or, err = client.decodeInstallationConfig(raw, in.OwnerSource.Name, in.OwnerSource.UID, false)
	if err != nil {
		return f, o, fr, or, until, err
	}
	o, until, err = s.owner.decodeOwnerConfiguration(data)
	o.ProtectionDigest = s.owner.protection.digest
	if err != nil || !o.Valid() || o.Suspended || o.Pool.IssuerEpoch != epoch || o.Pool.DeploymentUID != in.Activation.OwnerDeployment.UID || o.Pool.Deployment != in.Activation.OwnerDeployment.Name || !client.now().Before(until) {
		return f, o, fr, or, until, cfg.ErrUnavailable
	}
	return f, o, fr, or, identity.Earlier(f.FreshUntil, until), nil
}

func configurationProviderNativeEqual(a, b configurationProviderNative) bool {
	return a.guards == b.guards && equalJSON(a.resources, b.resources) && a.fleet.Revision == b.fleet.Revision && a.fleet.IssuerEpoch == b.fleet.IssuerEpoch && a.owner.Equal(b.owner) &&
		a.fleetRef == b.fleetRef && a.ownerRef == b.ownerRef && a.podName == b.podName && a.process == b.process && equalJSON(a.account, b.account) &&
		configurationProviderDeploymentEqual(a.deployment, b.deployment) && configurationProviderDeploymentEqual(a.ownerDeployment, b.ownerDeployment)
}

func configurationProviderDeploymentEqual(a, b apps.Deployment) bool {
	// Actual process startup may change status/RV. Both full original templates
	// are independently validated; metadata identity/spec cannot change here.
	return a.UID == b.UID && a.Name == b.Name && a.Namespace == b.Namespace && equalJSON(a.Spec, b.Spec) &&
		equalJSON(a.Labels, b.Labels) && equalJSON(a.Annotations, b.Annotations) && equalJSON(a.OwnerReferences, b.OwnerReferences) && equalJSON(a.Finalizers, b.Finalizers)
}
