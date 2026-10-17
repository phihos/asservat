package kubernetes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
)

// ErrInitialPreparationPolicyPending reports only an exact original policy
// waiting for API type checking. It permits bounded read-only observation, never
// another CREATE or replacement. Warnings and changed generation are not pending.
var ErrInitialPreparationPolicyPending = fmt.Errorf("%w: original policy compilation pending", cfg.ErrUnavailable)

func (s *InitialPreparer) FinalInputsEnabled() bool { return s != nil && s.services != nil }

func (s *InitialPreparer) checkedServices(v contracts.InitialPreparationServices) (contracts.InitialPreparationServices, error) {
	var zero contracts.InitialPreparationServices
	raw, e := json.Marshal(v)
	if !s.ActivationPreparationEnabled() || e != nil || len(raw) > 24<<10 || contracts.InitialInstallerFormatForServices(v.Format) == "" || v.Fleet.InstallationID != s.plan.InstallationID || !authorization.UUID(v.Fleet.IssuerEpoch) {
		return zero, cfg.ErrInvalid
	}
	fleet, _ := json.Marshal(v.Fleet)
	var decoded contracts.FleetSettings
	if _, e = decodePermissionSpec(fleet, s.protection.observer.validator.fleetSchema, &decoded); e != nil {
		return zero, cfg.ErrInvalid
	}
	if providerconfig.Validate(v.Kubernetes, v.Postgres, v.AuditStore, v.KeyService, s.protection.observer.now()) != nil {
		return zero, cfg.ErrInvalid
	}
	expected, _ := url.Parse(v.Kubernetes.Endpoint)
	actual := s.creator.api.Get().URL()
	// client-go adds its bounded timeout query to Request.URL. Compare the
	// independently validated origin/root path, never that generated request.
	if expected.Scheme != actual.Scheme || expected.Host != actual.Host || expected.Path != "" && expected.Path != "/" || actual.Path != "" && actual.Path != "/" {
		return zero, cfg.ErrInvalid
	}
	// This constructor owns a defensive copy; final runtime provider constructors
	// still validate their exact connection profile before any external effect.
	if json.Unmarshal(raw, &zero) != nil {
		return zero, cfg.ErrInvalid
	}
	return zero, nil
}
func (s *InitialPreparer) inputNames() []string {
	p := s.plan.Workload
	return []string{p.Witness, p.FleetSource, p.WorkloadGuard, p.WorkloadGuard, p.WitnessGuard, p.WitnessGuard, p.FleetGuard, p.FleetGuard, p.Configuration}
}
func (s *InitialPreparer) validPublicInputs(w contracts.InitialPreparationRoot) bool {
	if w.Activation == nil || w.Activation.Inputs == nil {
		return true
	}
	in := w.Activation.Inputs
	if w.Activation.Pod == nil || w.Activation.Pod.Receipt == nil || !preparationDigestValid(in.IntentDigest) || in.Creates == nil || len(in.Creates) > 9 {
		return false
	}
	names := s.inputNames()
	kinds := []string{"ConfigMap", "ConfigMap", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "ConfigMap"}
	seen := map[string]bool{w.Activation.Pod.OperationID: true}
	for _, c := range w.Creates {
		seen[c.OperationID] = true
	}
	for i, c := range in.Creates {
		if !authorization.UUID(c.OperationID) || seen[c.OperationID] || c.Kind != kinds[i] || c.Name != names[i] || !preparationDigestValid(c.SpecDigest) || !validPreparerReceipt(c.Receipt) || c.Receipt == nil && i != len(in.Creates)-1 {
			return false
		}
		seen[c.OperationID] = true
	}
	return true
}
func preparationRootRef(w contracts.InitialPreparationRoot, kind, name string) (contracts.WorkerObjectReference, error) {
	for _, v := range w.Creates {
		if v.Kind == kind && v.Name == name && v.Receipt != nil {
			return contracts.WorkerObjectReference{Name: name, UID: v.Receipt.UID}, nil
		}
	}
	return contracts.WorkerObjectReference{}, cfg.ErrChanged
}
func (s *InitialPreparer) inputConfiguration(w contracts.InitialPreparationRoot) (contracts.InitialInstaller, error) {
	var c contracts.InitialInstaller
	if s.services == nil || w.Activation == nil || w.Activation.Pod == nil || w.Activation.Pod.Receipt == nil {
		return c, cfg.ErrChanged
	}
	p := s.plan.Workload
	var e error
	c = contracts.InitialInstaller{Format: contracts.InitialInstallerFormatForServices(s.services.Format), InstallationID: s.plan.InstallationID, ClusterID: s.plan.ClusterID, IssuerEpoch: s.services.Fleet.IssuerEpoch, Pod: contracts.WorkerObjectReference{Name: p.Name, UID: w.Activation.Pod.Receipt.UID}, PodSpecDigest: w.Activation.Pod.SpecDigest, Configuration: p.Configuration, Kubernetes: s.services.Kubernetes, Postgres: s.services.Postgres, AuditStore: s.services.AuditStore, KeyService: s.services.KeyService}
	if s.plan.SchemaInitialization != "" {
		if s.plan.SchemaInitialization != contracts.InitialSchemaProtocol || w.Schema == nil || w.Schema.CompletedAt == nil || !s.validSchema(w) {
			return c, cfg.ErrChanged
		}
		v := w.Schema
		c.SchemaInitialization = s.plan.SchemaInitialization
		c.Schema = &contracts.InitialSchemaExpectation{BundleDigest: v.BundleDigest, Head: v.Head, DatabaseOID: v.DatabaseOID, PostmasterAt: v.PostmasterAt}
	} else if w.Schema != nil {
		return c, cfg.ErrChanged
	}
	if c.Namespace, e = preparationRootRef(w, "Namespace", p.Namespace); e != nil {
		return c, e
	}
	if c.WriterAccount, e = preparationRootRef(w, "ServiceAccount", p.WriterAccount); e != nil {
		return c, e
	}
	if c.ProbeAccount, e = preparationRootRef(w, "ServiceAccount", p.ProbeAccount); e != nil {
		return c, e
	}
	c.Handover = s.plan.Handover
	c.WorkloadGuard = contracts.OwnerDeploymentGuard{Name: p.WorkloadGuard, Administrators: append([]contracts.OwnerDeploymentActor(nil), s.plan.Administrators...)}
	c.FleetGuard = contracts.OwnerDeploymentGuard{Name: p.FleetGuard, Administrators: append([]contracts.OwnerDeploymentActor(nil), s.plan.Administrators...)}
	c.WitnessGuard = contracts.OwnerDeploymentGuard{Name: p.WitnessGuard, Administrators: append([]contracts.OwnerDeploymentActor(nil), s.plan.Administrators...)}
	c.WitnessGuard.Administrators = append(c.WitnessGuard.Administrators, contracts.OwnerDeploymentActor{Kind: "User", Name: "system:serviceaccount:" + p.Namespace + ":" + p.WriterAccount})
	if w.Activation.Inputs != nil {
		entries := w.Activation.Inputs.Creates
		if len(entries) > 0 && entries[0].Receipt != nil {
			c.Witness = contracts.WorkerObjectReference{Name: p.Witness, UID: entries[0].Receipt.UID}
		}
		if len(entries) > 1 && entries[1].Receipt != nil {
			c.FleetSource = contracts.WorkerObjectReference{Name: p.FleetSource, UID: entries[1].Receipt.UID}
		}
		for _, pair := range []struct {
			start int
			guard *contracts.OwnerDeploymentGuard
		}{{2, &c.WorkloadGuard}, {4, &c.WitnessGuard}, {6, &c.FleetGuard}} {
			if len(entries) > pair.start+1 && entries[pair.start].Receipt != nil && entries[pair.start+1].Receipt != nil {
				pair.guard.PolicyUID = entries[pair.start].Receipt.UID
				pair.guard.PolicyGeneration = 1
				pair.guard.BindingUID = entries[pair.start+1].Receipt.UID
				pair.guard.BindingResourceVersion = entries[pair.start+1].Receipt.ResourceVersion
			}
		}
	}
	return c, nil
}
func (s *InitialPreparer) publicInputResource(w contracts.InitialPreparationRoot, i int) (initialPreparationResource, error) {
	var out initialPreparationResource
	c, e := s.inputConfiguration(w)
	if e != nil || i < 0 || i >= 9 {
		return out, cfg.ErrChanged
	}
	p := s.plan.Workload
	ns := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	var object runtime.Object
	path := "/api/v1/namespaces/" + p.Namespace + "/configmaps"
	switch i {
	case 0:
		data, e := FreshInstallationWitnessData(c.InstallationID, c.IssuerEpoch, c.WriterAccount.UID)
		if e != nil {
			return out, e
		}
		object = &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: p.Witness, Namespace: p.Namespace}, Data: data}
	case 1:
		data, _ := json.Marshal(s.services.Fleet)
		object = &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: p.FleetSource, Namespace: p.Namespace}, Data: map[string]string{"fleet.json": string(data)}}
	case 2, 3:
		wp := cfg.InitialWorkloadAdministration{Handover: c.Handover == contracts.InitialPreparationHandoverProtocol, Name: p.WorkloadGuard, Configuration: p.Configuration, Witness: p.Witness, FleetSource: p.FleetSource, ControlNamespace: ns, PodName: p.Name, PodUID: c.Pod.UID, WriterAccount: p.WriterAccount, WriterAccountUID: c.WriterAccount.UID, ProbeAccount: p.ProbeAccount, ProbeAccountUID: c.ProbeAccount.UID}
		for _, a := range s.plan.Administrators {
			wp.Administrators = append(wp.Administrators, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
		}
		digest, e := hex.DecodeString(c.PodSpecDigest)
		if e != nil || len(digest) != 32 {
			return out, cfg.ErrChanged
		}
		copy(wp.PodSpecDigest[:], digest)
		policy, binding, e := InitialWorkloadAdmission(wp)
		if e != nil {
			return out, e
		}
		if i == 2 {
			object = policy
		} else {
			object = binding
		}
	case 4, 5, 6, 7:
		guard := c.WitnessGuard
		source := p.Witness
		if i >= 6 {
			guard = c.FleetGuard
			source = p.FleetSource
		}
		gp := cfg.ConfigMapAdministration{Name: guard.Name, SourceName: source, ControlNamespace: ns}
		for _, a := range guard.Administrators {
			gp.Administrators = append(gp.Administrators, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
		}
		var policy *admission.ValidatingAdmissionPolicy
		var binding *admission.ValidatingAdmissionPolicyBinding
		if i < 6 {
			policy, binding, e = InstallationWitnessAdmission(gp)
		} else {
			policy, binding, e = FleetConfigurationAdmission(gp)
		}
		if e != nil {
			return out, e
		}
		if i%2 == 0 {
			object = policy
		} else {
			object = binding
		}
	case 8:
		if len(w.Activation.Inputs.Creates) < 8 {
			return out, cfg.ErrChanged
		}
		for _, entry := range w.Activation.Inputs.Creates[:8] {
			if entry.Receipt == nil {
				return out, cfg.ErrChanged
			}
		}
		data, e := json.Marshal(c)
		if e != nil || len(data) > 32<<10 {
			return out, cfg.ErrInvalid
		}
		object = &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: p.Configuration, Namespace: p.Namespace}, Immutable: ptr.To(true), Data: map[string]string{"deployment.json": string(data)}}
	}
	switch object.(type) {
	case *admission.ValidatingAdmissionPolicy:
		object.GetObjectKind().SetGroupVersionKind(admission.SchemeGroupVersion.WithKind("ValidatingAdmissionPolicy"))
		path = "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies"
	case *admission.ValidatingAdmissionPolicyBinding:
		object.GetObjectKind().SetGroupVersionKind(admission.SchemeGroupVersion.WithKind("ValidatingAdmissionPolicyBinding"))
		path = "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings"
	}
	return initialPreparationResource{object: object, path: path, namespace: preparerMetadata(object).Namespace, digest: preparationDigest(object)}, nil
}

func (s *InitialPreparer) verifyPublicInput(raw []byte, o initialPreparationResource, intent contracts.InitialPreparationCreate) (contracts.InitialPreparationReceipt, error) {
	if _, ok := o.object.(*core.ConfigMap); !ok {
		if _, ok := o.object.(*admission.ValidatingAdmissionPolicyBinding); ok && intent.Receipt != nil {
			var binding admission.ValidatingAdmissionPolicyBinding
			if strictGuardJSON(raw, &binding) != nil || binding.ResourceVersion != intent.Receipt.ResourceVersion {
				return contracts.InitialPreparationReceipt{}, cfg.ErrChanged
			}
		}
		if _, ok := o.object.(*admission.ValidatingAdmissionPolicy); ok {
			var policy admission.ValidatingAdmissionPolicy
			if strictGuardJSON(raw, &policy) != nil || policy.Generation != 1 {
				return contracts.InitialPreparationReceipt{}, cfg.ErrChanged
			}
			if policy.Status.TypeChecking != nil && len(policy.Status.TypeChecking.ExpressionWarnings) != 0 {
				return contracts.InitialPreparationReceipt{}, cfg.ErrChanged
			}
			if policy.Status.ObservedGeneration != policy.Generation || policy.Status.TypeChecking == nil {
				return contracts.InitialPreparationReceipt{}, ErrInitialPreparationPolicyPending
			}
		}
		_, receipt, e := s.verified(raw, o, intent, false)
		return receipt, e
	}
	var v core.ConfigMap
	if permissionJSON(raw, 64<<10, 16384) != nil || strictGuardJSON(raw, &v) != nil || !s.creator.owns(v.ObjectMeta, intent.Name) || v.Namespace != o.namespace || len(v.Annotations) != 3 || v.Annotations[initialPreparationOperationAnnotation] != intent.OperationID || len(v.Labels) != 0 || len(v.Finalizers) != 0 || len(v.OwnerReferences) != 0 || intent.Receipt != nil && intent.Receipt.UID != string(v.UID) {
		return contracts.InitialPreparationReceipt{}, cfg.ErrChanged
	}
	receipt := contracts.InitialPreparationReceipt{UID: string(v.UID), ResourceVersion: v.ResourceVersion}
	v.ObjectMeta = meta.ObjectMeta{Name: intent.Name, Namespace: o.namespace}
	if !equalJSON(v, o.object) {
		return contracts.InitialPreparationReceipt{}, cfg.ErrChanged
	}
	return receipt, nil
}

// EnsureNextPublicInput admits one closed typed effect. An already-pending
// record never gets another POST, even if the target is currently absent.
func (s *InitialPreparer) EnsureNextPublicInput(ctx context.Context) (contracts.InitialPreparationRoot, error) {
	var zero contracts.InitialPreparationRoot
	if s == nil || s.services == nil || ctx == nil {
		return zero, cfg.ErrInvalid
	}
	ctx, joined, e := s.ownPodRequest(ctx)
	if e != nil {
		return zero, e
	}
	defer joined()
	until, e := s.current(ctx)
	if e != nil {
		return zero, e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	cm, w, e := s.read(ctx)
	if e != nil || w.Phase != "declared" || w.Activation == nil || w.Activation.Pod == nil || w.Activation.Pod.Receipt == nil {
		return zero, cfg.ErrChanged
	}
	raw, e := s.creator.raw(ctx, "/api/v1/namespaces/"+s.plan.Workload.Namespace+"/pods/"+s.plan.Workload.Name, nil)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	if _, _, e = s.verifiedGatedPod(raw, *w.Activation.Pod); e != nil {
		return zero, e
	}
	digest := preparationDigest(*s.services)
	if w.Activation.Inputs == nil && w.Activation.Credentials != nil {
		return zero, cfg.ErrChanged
	}
	if w.Activation.Inputs == nil {
		w.Activation.Inputs = &contracts.InitialPreparationPublicInputs{IntentDigest: digest, Creates: []contracts.InitialPreparationCreate{}}
		if e = s.write(ctx, cm, w, until); e != nil {
			return zero, e
		}
		cm, w, e = s.read(ctx)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
	}
	if w.Activation.Inputs.IntentDigest != digest {
		return zero, cfg.ErrChanged
	}
	index := 0
	for index < len(w.Activation.Inputs.Creates) && w.Activation.Inputs.Creates[index].Receipt != nil {
		o, e := s.publicInputResource(w, index)
		if e != nil {
			return zero, e
		}
		entry := w.Activation.Inputs.Creates[index]
		raw, e := s.creator.raw(ctx, o.path+"/"+entry.Name, nil)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
		if entry.SpecDigest != o.digest {
			return zero, cfg.ErrChanged
		}
		if _, e = s.verifyPublicInput(raw, o, entry); e != nil {
			return zero, e
		}
		index++
	}
	if index == 9 {
		return w, s.finish(ctx, until)
	}
	o, e := s.publicInputResource(w, index)
	if e != nil {
		return zero, e
	}
	fresh := false
	if index == len(w.Activation.Inputs.Creates) {
		id, e := prepUUID()
		if e != nil {
			return zero, e
		}
		w.Activation.Inputs.Creates = append(w.Activation.Inputs.Creates, contracts.InitialPreparationCreate{OperationID: id, Kind: o.object.GetObjectKind().GroupVersionKind().Kind, Name: preparerMetadata(o.object).Name, SpecDigest: o.digest})
		if e = s.write(ctx, cm, w, until); e != nil {
			return zero, e
		}
		fresh = true
		cm, w, e = s.read(ctx)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
	}
	intent := w.Activation.Inputs.Creates[index]
	if intent.SpecDigest != o.digest {
		return zero, cfg.ErrChanged
	}
	if fresh {
		if e = s.finish(ctx, until); e != nil {
			return zero, e
		}
		object := o.object.DeepCopyObject()
		m := preparerMetadata(object)
		s.creator.stamp(m)
		m.Annotations[initialPreparationOperationAnnotation] = intent.OperationID
		_, e = s.creator.post(ctx, o.path, object)
		if e == cfg.ErrDenied {
			return zero, e
		}
	}
	raw, e = s.creator.raw(ctx, o.path+"/"+intent.Name, nil)
	if apierrors.IsNotFound(e) {
		return zero, cfg.ErrUnavailable
	}
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	receipt, e := s.verifyPublicInput(raw, o, intent)
	if e != nil {
		return zero, e
	}
	if e = s.finish(ctx, until); e != nil {
		return zero, e
	}
	if intent.Receipt == nil {
		w.Activation.Inputs.Creates[index].Receipt = &receipt
		if e = s.write(ctx, cm, w, until); e != nil {
			return zero, e
		}
	}
	return w, nil
}
func (s *InitialPreparer) PrepareFinalInputs(ctx context.Context) (contracts.InitialPreparationRoot, error) {
	for step := 0; step < 10; step++ {
		w, e := s.EnsureNextPublicInput(ctx)
		if e != nil {
			return w, e
		}
		if len(w.Activation.Inputs.Creates) == 9 && w.Activation.Inputs.Creates[8].Receipt != nil {
			return w, nil
		}
	}
	return contracts.InitialPreparationRoot{}, cfg.ErrUnavailable
}
