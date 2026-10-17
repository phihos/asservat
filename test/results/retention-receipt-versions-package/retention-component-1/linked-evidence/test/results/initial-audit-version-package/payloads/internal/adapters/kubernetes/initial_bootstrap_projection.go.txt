package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
)

func bootstrapStepRef(s contracts.InitialBootstrapState, index int, name string) (contracts.WorkerObjectReference, error) {
	if index < 0 || index >= len(s.Creates) || s.Creates[index].Step != bootstrapSteps[index] || s.Creates[index].Receipt == nil {
		return contracts.WorkerObjectReference{}, cfg.ErrUnavailable
	}
	return contracts.WorkerObjectReference{Name: name, UID: s.Creates[index].Receipt.UID}, nil
}
func bootstrapPlan(d contracts.InitialBootstrap, s contracts.InitialBootstrapState) (contracts.InitialPreparationPlan, error) {
	var zero contracts.InitialPreparationPlan
	if s.Manager == nil || s.Manager.Receipt == nil {
		return zero, cfg.ErrUnavailable
	}
	n := bootstrapNames(d)
	private, e := bootstrapStepRef(s, 0, n.private)
	if e != nil {
		return zero, e
	}
	w := bootstrapWorkload(d)
	manager := *s.Manager.Receipt
	probe := s.Prelude.Account
	return contracts.InitialPreparationPlan{SchemaInitialization: contracts.InitialSchemaProtocol, Handover: contracts.InitialPreparationHandoverProtocol, HistoryManager: &manager, HistoryProbe: &probe, ProbeAudience: d.ProbeAudience, PrivateState: &private, Continuation: contracts.InitialPreparationActivationProtocol, InstallationID: s.InstallationID, RequestID: s.RequestID, ClusterID: s.ClusterID, BootstrapNamespace: s.Prelude.Namespace, RootName: n.root, ProbeName: n.continuityMarker, ContinuityName: n.continuity, Administrators: append([]contracts.OwnerDeploymentActor(nil), d.Administrators...), Workload: contracts.InitialPreparationWorkload{RegistryAuthentication: w.RegistryAuthentication, Namespace: w.Namespace, Name: w.Name, WriterAccount: w.WriterAccount, ProbeAccount: w.ProbeAccount, Configuration: w.Configuration, Credentials: w.Credentials, Image: w.Image, Witness: w.Witness, FleetSource: w.FleetSource, WitnessGuard: w.WitnessGuard, FleetGuard: w.FleetGuard, WorkloadGuard: w.WorkloadGuard, StagingGuard: d.TargetNamespace + "-" + d.Name + "-staging", Journal: d.Name + "-journal"}}, nil
}
func bootstrapPrivateObject(d contracts.InitialBootstrap, s contracts.InitialBootstrapState, index int) (runtime.Object, error) {
	n := bootstrapNames(d)
	name, key := "", ""
	var payload any
	immutable := true
	switch index {
	case 0:
		name, key = n.private, "state.json"
		immutable = false
		payload = contracts.InitialPreparationPrivateState{Format: contracts.InitialPreparationPrivateFormat, InstallationID: s.InstallationID, RequestID: s.RequestID}
	case 1:
		name, key = n.sqlMaterial, "material.json"
		payload = contracts.InitialSQLMaterial{Format: contracts.InitialSQLMaterialFormat, InstallationID: s.InstallationID, RequestID: s.RequestID, PreparationPassword: s.Passwords.Preparation, AuditPassword: s.Passwords.Audit, ActivationPassword: s.Passwords.Activation}
	case 2:
		if s.Material == nil {
			return nil, cfg.ErrUnavailable
		}
		name, key = n.providerMaterial, "material.json"
		payload = contracts.InitialProviderMaterial{Format: contracts.InitialProviderMaterialFormat, InstallationID: s.InstallationID, RequestID: s.RequestID, IssuerToken: s.Material.IssuerToken, Storage: s.Material.Storage, StorageUseUntil: s.Material.StorageUseUntil, RegistryConfig: s.Material.RegistryConfig}
	default:
		return nil, cfg.ErrInvalid
	}
	b, e := json.Marshal(payload)
	if e != nil || index == 2 && len(b) > contracts.InitialProviderMaterialMaxBytes {
		clear(b)
		return nil, cfg.ErrInvalid
	}
	m := bootstrapMeta(d, name)
	m.Annotations[initialNamespaceInstallationAnnotation] = s.InstallationID
	m.Annotations[initialNamespaceRequestAnnotation] = s.RequestID
	return &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: m, Type: core.SecretTypeOpaque, Immutable: ptr.To(immutable), Data: map[string][]byte{key: b}}, nil
}

func (s *InitialBootstrap) stepObject(ctx context.Context, state contracts.InitialBootstrapState, index int) (string, runtime.Object, error) {
	base := "/api/v1/namespaces/" + s.desired.BootstrapNamespace
	if index < 3 {
		o, e := bootstrapPrivateObject(s.desired, state, index)
		return base + "/secrets", o, e
	}
	plan, e := bootstrapPlan(s.desired, state)
	if e != nil {
		return "", nil, e
	}
	var object runtime.Object
	var path string
	switch index {
	case 3, 4:
		p, b, e := InitialPreparationContinuityAdmission(plan)
		if e != nil {
			return "", nil, e
		}
		object, path = p, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies"
		if index == 4 {
			object, path = b, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings"
		}
	case 5, 6:
		p, b, e := InitialNamespaceAdmission(preparerAdministration(plan))
		if e != nil {
			return "", nil, e
		}
		object, path = p, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies"
		if index == 6 {
			object, path = b, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings"
		}
	case 7:
		projection, e := s.projection(ctx, state)
		if e != nil {
			return "", nil, e
		}
		object, e = bootstrapProjectionObject(s.desired, state, projection)
		if e != nil {
			return "", nil, e
		}
		path = base + "/configmaps"
	default:
		return "", nil, cfg.ErrInvalid
	}
	return path, object, nil
}
func bootstrapProjectionValue(d contracts.InitialBootstrap, state contracts.InitialBootstrapState) (contracts.InitialPreparer, error) {
	var zero contracts.InitialPreparer
	n := bootstrapNames(d)
	plan, e := bootstrapPlan(d, state)
	if e != nil {
		return zero, e
	}
	sql, e := bootstrapStepRef(state, 1, n.sqlMaterial)
	if e != nil {
		return zero, e
	}
	provider, e := bootstrapStepRef(state, 2, n.providerMaterial)
	if e != nil {
		return zero, e
	}
	guard := func(policyIndex, bindingIndex int, name string) (contracts.OwnerDeploymentGuard, error) {
		pRef, e := bootstrapStepRef(state, policyIndex, name)
		if e != nil {
			return contracts.OwnerDeploymentGuard{}, e
		}
		bRef, e := bootstrapStepRef(state, bindingIndex, name)
		if e != nil {
			return contracts.OwnerDeploymentGuard{}, e
		}
		// The active first projection below independently requires native
		// generation one. These retained pins remain original provenance after
		// handover legitimately retires the staging policy.
		return contracts.OwnerDeploymentGuard{Name: name, PolicyUID: pRef.UID, PolicyGeneration: 1, BindingUID: bRef.UID, BindingResourceVersion: state.Creates[bindingIndex].Receipt.ResourceVersion, Administrators: append([]contracts.OwnerDeploymentActor(nil), d.Administrators...)}, nil
	}
	continuity, e := guard(3, 4, n.continuity)
	if e != nil {
		return zero, e
	}
	staging, e := guard(5, 6, plan.Workload.StagingGuard)
	if e != nil {
		return zero, e
	}
	servicesFormat := contracts.InitialPreparationServicesFormat
	if d.Format == contracts.InitialBootstrapVersionedAuditFormat {
		servicesFormat = contracts.InitialPreparationVersionedAuditServicesFormat
	}
	return contracts.InitialPreparer{Format: contracts.InitialPreparerFormat, Plan: plan, Continuity: continuity, Staging: staging, Kubernetes: d.Kubernetes, SQLMaterial: &sql, Services: &contracts.InitialPreparationServices{Format: servicesFormat, Fleet: bootstrapFleet(d, state.InstallationID, state.IssuerEpoch), Kubernetes: d.Kubernetes, Postgres: d.Postgres, AuditStore: d.AuditStore, KeyService: d.KeyService}, Providers: &contracts.InitialProviderProfile{Format: contracts.InitialProviderProfileFormat, Material: provider, IssuerPolicy: d.Providers.IssuerPolicy, WrapRole: d.Providers.WrapRole, WrapPolicy: d.Providers.WrapPolicy, UnwrapRole: d.Providers.UnwrapRole, UnwrapPolicy: d.Providers.UnwrapPolicy}}, nil
}
func (s *InitialBootstrap) projection(ctx context.Context, state contracts.InitialBootstrapState) (contracts.InitialPreparer, error) {
	var zero contracts.InitialPreparer
	projection, e := bootstrapProjectionValue(s.desired, state)
	if e != nil {
		return zero, e
	}
	for _, pin := range []contracts.OwnerDeploymentGuard{projection.Continuity, projection.Staging} {
		name := pin.Name
		var p admission.ValidatingAdmissionPolicy
		var b admission.ValidatingAdmissionPolicyBinding
		raw, e := s.get(ctx, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/"+name)
		if e != nil || strictGuardJSON(raw, &p) != nil || string(p.UID) != pin.PolicyUID || p.Generation != 1 || p.DeletionTimestamp != nil {
			return zero, cfg.ErrChanged
		}
		if p.Status.ObservedGeneration != p.Generation || p.Status.TypeChecking == nil {
			return zero, ErrInitialPreparationPolicyPending
		}
		if len(p.Status.TypeChecking.ExpressionWarnings) != 0 {
			return zero, cfg.ErrChanged
		}
		raw, e = s.get(ctx, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/"+name)
		if e != nil || strictGuardJSON(raw, &b) != nil || string(b.UID) != pin.BindingUID || b.ResourceVersion != pin.BindingResourceVersion || b.DeletionTimestamp != nil {
			return zero, cfg.ErrChanged
		}
	}
	// Same concrete independent current proof as initial-prepare, without
	// creating its root, target namespace, SQL role or provider credential.
	checker, e := NewInitialPreparer(s.config, s.proof.observer, s.proof.probe, projection)
	if e != nil {
		return zero, e
	}
	defer checker.Close()
	if _, e = checker.current(ctx); e != nil {
		return zero, e
	}
	return projection, nil
}

// PrepareProjection advances at most one fixed original create. Unknown claims
// and CREATE replies never get another POST; the exact original object may be
// read and independently verified. No caller supplies a body, UID or retry ID.
func (s *InitialBootstrap) PrepareProjection(ctx context.Context) (contracts.InitialPreparer, bool, error) {
	var zero contracts.InitialPreparer
	bounded, end, e := s.enter(ctx)
	if e != nil {
		return zero, false, e
	}
	defer end()
	if s.seedUID == "" {
		return zero, false, cfg.ErrInvalid
	}
	if e = s.current(bounded); e != nil {
		return zero, false, e
	}
	secret, state, e := s.readSeed(bounded)
	if e != nil {
		return zero, false, e
	}
	if state.Projection != nil {
		return s.readProjection(bounded, state)
	}
	if state.Manager == nil || state.Manager.Receipt == nil || state.Manager.Closing != nil || state.Retired || !time.Now().Before(state.Manager.Until) {
		return zero, false, cfg.ErrChanged
	}
	bounded, stop := context.WithDeadline(bounded, state.Manager.Until)
	defer stop()
	index := len(state.Creates)
	fresh := false
	if index > 0 && state.Creates[index-1].Receipt == nil {
		index--
	}
	if index == len(bootstrapSteps) {
		next := state
		next.Projection = &contracts.WorkerObjectReference{Name: bootstrapNames(s.desired).projection, UID: state.Creates[index-1].Receipt.UID}
		if e = s.updateSeed(bounded, secret, state, next); e != nil {
			return zero, false, e
		}
		return s.readProjection(bounded, next)
	}
	original := state
	if index == len(state.Creates) {
		id, e := prepUUID()
		if e != nil {
			return zero, false, e
		}
		state.Creates = append(append([]contracts.InitialBootstrapCreate{}, state.Creates...), contracts.InitialBootstrapCreate{Step: bootstrapSteps[index], OperationID: id})
		fresh = true
	}
	// Assemble and independently check the complete body before spending the
	// one create claim. Native policy type checking can still be Pending; that
	// read-only condition must not strand an acknowledged but unsent CREATE.
	path, want, e := s.stepObject(bounded, state, index)
	if e != nil {
		return zero, false, e
	}
	if v, ok := want.(*core.Secret); ok {
		defer func() {
			for _, b := range v.Data {
				clear(b)
			}
		}()
	}
	if fresh {
		if e = s.updateSeed(bounded, secret, original, state); e != nil {
			return zero, false, e
		}
	}
	m := bootstrapObjectMetadata(want)
	if m.Annotations == nil {
		m.Annotations = map[string]string{}
	}
	m.Annotations["asservat.io/bootstrap-operation-id"] = state.Creates[index].OperationID
	full := path + "/" + m.Name
	raw, e := s.get(bounded, full)
	if apierrors.IsNotFound(e) && fresh {
		if e = s.current(bounded); e != nil {
			return zero, false, e
		}
		raw, e = s.api.Post().AbsPath(path).Param("fieldValidation", "Strict").MaxRetries(0).Body(want).DoRaw(bounded)
		if e != nil {
			raw, e = s.get(bounded, full)
		}
	} else if e == nil && fresh {
		// A preexisting object was not produced by this new acknowledged intent.
		return zero, false, cfg.ErrChanged
	}
	defer clear(raw)
	if e != nil {
		return zero, false, cfg.ErrUnavailable
	}
	got := bootstrapEmptyObject(want)
	if strictGuardJSON(raw, got) != nil || !bootstrapObjectMatches(want, got) {
		return zero, false, cfg.ErrChanged
	}
	if v, ok := got.(*core.Secret); ok {
		defer func() {
			for _, b := range v.Data {
				clear(b)
			}
		}()
	}
	secret, current, e := s.readSeed(bounded)
	if e != nil || !equalJSON(current, state) {
		return zero, false, cfg.ErrChanged
	}
	next := state
	next.Creates = append([]contracts.InitialBootstrapCreate{}, state.Creates...)
	meta := bootstrapObjectMetadata(got)
	next.Creates[index].Receipt = &contracts.InitialPreparationReceipt{UID: string(meta.UID), ResourceVersion: meta.ResourceVersion}
	if e = s.updateSeed(bounded, secret, state, next); e != nil {
		return zero, false, e
	}
	return zero, false, nil
}

func (s *InitialBootstrap) readProjection(ctx context.Context, state contracts.InitialBootstrapState) (contracts.InitialPreparer, bool, error) {
	var zero contracts.InitialPreparer
	if state.Projection == nil {
		return zero, false, cfg.ErrUnavailable
	}
	raw, e := s.get(ctx, "/api/v1/namespaces/"+s.desired.BootstrapNamespace+"/configmaps/"+state.Projection.Name)
	var cm core.ConfigMap
	if e != nil || strictGuardJSON(raw, &cm) != nil || string(cm.UID) != state.Projection.UID || cm.Immutable == nil || !*cm.Immutable || cm.DeletionTimestamp != nil || len(cm.OwnerReferences) != 0 || len(cm.Finalizers) != 0 || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return zero, false, cfg.ErrChanged
	}
	actual, e := contracts.DecodeInitialPreparer(bytes.NewBufferString(cm.Data["deployment.json"]))
	if e != nil {
		return zero, false, cfg.ErrChanged
	}
	// Reading the immutable projection grants no setup effects. Original
	// staging pins may be historical after completed handover; the existing
	// preparer independently selects its passive completed-history path.
	want, e := bootstrapProjectionValue(s.desired, state)
	if e != nil || !equalJSON(actual, want) {
		return zero, false, cfg.ErrChanged
	}
	expected, e := bootstrapProjectionObject(s.desired, state, want)
	if e != nil || !bootstrapObjectMatches(expected, &cm) || cm.ResourceVersion != state.Creates[7].Receipt.ResourceVersion {
		return zero, false, cfg.ErrChanged
	}
	if e = s.current(ctx); e != nil {
		return zero, false, e
	}
	return actual, true, nil
}

func bootstrapProjectionObject(d contracts.InitialBootstrap, state contracts.InitialBootstrapState, projection contracts.InitialPreparer) (*core.ConfigMap, error) {
	if len(state.Creates) < 8 || state.Creates[7].Step != bootstrapSteps[7] {
		return nil, cfg.ErrInvalid
	}
	b, e := json.Marshal(projection)
	if e != nil || len(b) > contracts.InitialPreparationMaxBytes {
		return nil, cfg.ErrInvalid
	}
	m := bootstrapMeta(d, bootstrapNames(d).projection)
	m.Annotations["asservat.io/bootstrap-operation-id"] = state.Creates[7].OperationID
	return &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: m, Immutable: ptr.To(true), Data: map[string]string{"deployment.json": string(b)}}, nil
}
