package kubernetes

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// CopiesClosed is a historical disposition only. It never permits a DELETE or
// substitutes for independently observed original handover and native guards.
func (s *InitialBootstrapCopyState) CopiesClosed() bool { return s != nil && s.complete() }

// AdvanceManagedCopies advances at most one fixed positive closure step. The
// original private inputs are never read here. The supplied concrete history
// reader is installation-owned, independently scoped and read-only. No public
// transport can supply an observation, completion flag, UID or cleanup date.
func (s *InitialBootstrap) AdvanceManagedCopies(ctx context.Context, history app.InitialInstallationHistory) (bool, error) {
	if s == nil || ctx == nil || history == nil || !contracts.InitialBootstrapHasCopyClosure(s.desired.Format) {
		return false, cfg.ErrInvalid
	}
	p, err := s.ReadPassiveHistory(ctx)
	if err != nil || p == nil || p.ManagerRetirement == nil {
		return false, cfg.ErrUnavailable
	}
	bounded, stop := context.WithDeadline(ctx, p.ValidUntil)
	defer stop()
	bounded, end, err := s.enter(bounded)
	if err != nil {
		return false, err
	}
	defer end()
	if err = s.current(bounded); err != nil {
		return false, err
	}
	preparer, err := NewInitialPreparer(s.config, s.proof.observer, s.proof.probe, p.Bundle.Configuration)
	if err != nil {
		return false, err
	}
	defer preparer.Close()
	root, passive, err := preparer.ReadHandover(bounded)
	if err != nil || !passive || !preparer.HandoverCleanupComplete(root) || !authorization.UUID(root.RootUID) {
		return false, cfg.ErrUnavailable
	}
	observed, err := history.ObserveInitialInstallation(bounded)
	if err != nil || observed.Disposition != app.InitialInstallationActivated || observed.Record == nil || !observed.Record.Valid() || observed.Record.Scope.InstallationID != p.Bundle.Observation.InstallationID || observed.Record.Claim.ID != root.Activation.Handover.Cleanup.ActivatedClaimID || !time.Now().Before(observed.ValidUntil) || bounded.Err() != nil {
		return false, cfg.ErrUnavailable
	}
	bounded, finish := context.WithDeadline(bounded, observed.ValidUntil)
	defer finish()
	m, locator, err := s.readPassiveMetadata(bounded)
	if err != nil || locator == nil || string(m.UID) != p.Bundle.Seed.UID {
		return false, cfg.ErrChanged
	}
	current, err := bootstrapReadCopyState(s.desired, m, p)
	if err != nil {
		return false, err
	}
	if current == nil {
		c := contracts.InitialBootstrapCopyClaim{Format: contracts.InitialBootstrapCopyClaimFormat, InstallationID: p.Bundle.Observation.InstallationID, RequestID: p.Bundle.Observation.RequestID, Namespace: p.Bundle.Observation.Prelude.Namespace, Seed: p.Bundle.Seed, Projection: p.Bundle.Observation.Projection, History: locator.History, Root: contracts.WorkerObjectReference{Name: p.Bundle.Configuration.Plan.RootName, UID: root.RootUID}, ManagerCloseID: p.ManagerRetirement.OperationID, ManagerRetiredAt: p.ManagerRetirement.RetiredAt, ActivatedClaimID: observed.Record.Claim.ID, StartedAt: time.Now().UTC().Truncate(time.Microsecond)}
		c.Until = c.StartedAt.Add(contracts.InitialBootstrapCopyCleanupDuration)
		if p.Bundle.Configuration.SQLMaterial == nil || p.Bundle.Configuration.Providers == nil {
			return false, cfg.ErrChanged
		}
		c.SQL = *p.Bundle.Configuration.SQLMaterial
		c.Provider = p.Bundle.Configuration.Providers.Material
		for _, id := range []*string{&c.OperationID, &c.PolicyOperationID, &c.BindingOperationID} {
			*id, err = prepUUID()
			if err != nil {
				return false, err
			}
		}
		if !bootstrapCopyClaimValid(s.desired, c) {
			return false, cfg.ErrInvalid
		}
		// Both exact copies must still exist before the one cleanup claim. Missing
		// objects do not manufacture a successful prior removal or a new interval.
		for _, ref := range []contracts.WorkerObjectReference{c.SQL, c.Provider} {
			if _, err = s.copyMetadata(bounded, c, ref, "", false); err != nil {
				return false, err
			}
		}
		body, _ := json.Marshal(c)
		_, err = s.copyAnnotation(bounded, m, bootstrapCopyClaimAnnotation, string(body), false)
		return false, err
	}
	if current.Claim.Root.UID != root.RootUID || current.Claim.ActivatedClaimID != observed.Record.Claim.ID {
		return false, cfg.ErrChanged
	}
	if current.complete() {
		return true, s.copyCurrent(bounded, p, current)
	}
	if !time.Now().Before(current.Claim.Until) {
		return false, cfg.ErrUnavailable
	}
	bounded, done := context.WithDeadline(bounded, current.Claim.Until)
	defer done()
	if err = s.current(bounded); err != nil {
		return false, err
	}
	policy, binding, err := InitialBootstrapCopyAdmission(s.desired, current.Claim)
	if err != nil {
		return false, err
	}
	if current.Policy == nil {
		return false, s.advanceCopyGuard(bounded, m, current, policy, true)
	}
	if current.Binding == nil {
		return false, s.advanceCopyGuard(bounded, m, current, binding, false)
	}
	// Positive independently denied tombstone precedes all metadata marks and
	// DELETEs. The product retains both guards and rechecks their exact current
	// identities; trusted administrator/RBAC ownership protects their retention.
	if err = s.copyCurrent(bounded, p, current); err != nil {
		return false, err
	}
	if current.SQLRemoved == nil {
		return false, s.advanceCopyDelete(bounded, m, current, current.Claim.SQL, current.SQLMarked, bootstrapCopySQLMarkedAnnotation, bootstrapCopySQLAnnotation)
	}
	if current.ProviderRemoved == nil {
		return false, s.advanceCopyDelete(bounded, m, current, current.Claim.Provider, current.ProviderMarked, bootstrapCopyProviderMarkedAnnotation, bootstrapCopyProviderAnnotation)
	}
	for _, ref := range []contracts.WorkerObjectReference{current.Claim.SQL, current.Claim.Provider} {
		_, err := s.copyMetadata(bounded, current.Claim, ref, current.Claim.OperationID, true)
		if !apierrors.IsNotFound(err) {
			return false, cfg.ErrChanged
		}
	}
	if err = s.copyCurrent(bounded, p, current); err != nil {
		return false, err
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	_, err = s.copyAnnotation(bounded, m, bootstrapCopyCompleteAnnotation, at.Format(time.RFC3339Nano), true)
	return err == nil, err
}

func (s *InitialBootstrap) copyCurrent(ctx context.Context, p *InitialBootstrapPassiveRead, state *InitialBootstrapCopyState) error {
	if state == nil || state.Policy == nil || state.Binding == nil || p.Bundle.Observation.Prelude.CopyMarker == nil {
		return cfg.ErrInvalid
	}
	if err := s.current(ctx); err != nil {
		return err
	}
	policy, binding, err := InitialBootstrapCopyAdmission(s.desired, state.Claim)
	if err != nil {
		return err
	}
	plan := cfg.ConfigMapAdministration{Name: policy.Name, SourceName: p.Bundle.Observation.Prelude.CopyMarker.Name, ControlNamespace: cfg.NamespaceRef{Name: state.Claim.Namespace.Name, UID: state.Claim.Namespace.UID}}
	for _, a := range s.desired.Administrators {
		plan.Administrators = append(plan.Administrators, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
	}
	pin := GuardPin{PolicyUID: state.Policy.UID, PolicyGeneration: 1, BindingUID: state.Binding.UID, BindingResourceVersion: state.Binding.ResourceVersion}
	proof, err := newConfigMapProtection(s.proof.observer, s.proof.probe, plan, pin, "initial-bootstrap-copy-tombstone", bootstrapCopyDenial)
	if err != nil {
		return err
	}
	normalizePermissionPolicy(&policy.Spec)
	proof.policy, proof.binding = policy.Spec, binding.Spec
	_, until, err := proof.current(ctx)
	if err != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return cfg.ErrUnavailable
	}
	return nil
}

// copyAnnotation is an exact metadata CAS. The API is requested to return only
// PartialObjectMetadata; there is no broad Secret fallback. A lost reply is
// recovered by the original UID and unchanged fixed annotation, never by a new
// claim or recreated seed. The final CAS also irreversibly sanitizes its data.
func (s *InitialBootstrap) copyAnnotation(ctx context.Context, m *meta.PartialObjectMetadata, key, value string, sanitize bool) (*meta.PartialObjectMetadata, error) {
	return s.copyAnnotationMode(ctx, m, key, value, sanitize, false)
}
func (s *InitialBootstrap) copyAnnotationMode(ctx context.Context, m *meta.PartialObjectMetadata, key, value string, sanitize, requireAcknowledgement bool) (*meta.PartialObjectMetadata, error) {
	if m == nil || m.Annotations[key] != "" || ctx.Err() != nil {
		return nil, cfg.ErrChanged
	}
	if err := s.current(ctx); err != nil {
		return nil, err
	}
	op := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": string(m.UID)}, {"op": "test", "path": "/metadata/resourceVersion", "value": m.ResourceVersion}, {"op": "add", "path": "/metadata/annotations/" + strings.ReplaceAll(key, "/", "~1"), "value": value}}
	if sanitize {
		op = append(op, map[string]any{"op": "replace", "path": "/data", "value": map[string]string{"retired": "dHJ1ZQ=="}}, map[string]any{"op": "add", "path": "/immutable", "value": true})
	}
	body, err := json.Marshal(op)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	raw, writeErr := s.api.Patch(types.JSONPatchType).AbsPath("/api/v1/namespaces/"+s.desired.BootstrapNamespace+"/secrets/"+m.Name).SetHeader("Accept", bootstrapPartialMetadataAccept).Param("fieldValidation", "Strict").Body(body).MaxRetries(0).DoRaw(ctx)
	var reply meta.PartialObjectMetadata
	acknowledged := writeErr == nil && permissionJSON(raw, 16<<10, 4096) == nil && strictGuardJSON(raw, &reply) == nil && reply.APIVersion == "meta.k8s.io/v1" && reply.Kind == "PartialObjectMetadata" && reply.UID == m.UID && reply.Annotations[key] == value
	clear(raw)
	if requireAcknowledgement && !acknowledged {
		return nil, cfg.ErrUnavailable
	}
	actual, _, err := s.readPassiveMetadata(ctx)
	if err != nil || actual.UID != m.UID || actual.Annotations[key] != value || len(actual.Annotations) != len(m.Annotations)+1 {
		return nil, cfg.ErrUnavailable
	}
	for k, v := range m.Annotations {
		if actual.Annotations[k] != v {
			return nil, cfg.ErrChanged
		}
	}
	if ctx.Err() != nil {
		return nil, cfg.ErrUnavailable
	}
	return actual, nil
}

func (s *InitialBootstrap) advanceCopyGuard(ctx context.Context, m *meta.PartialObjectMetadata, state *InitialBootstrapCopyState, want runtime.Object, policy bool) error {
	claimed, startedKey, receiptKey, path := state.BindingStartedAt, bootstrapCopyBindingStartedAnnotation, bootstrapCopyBindingAnnotation, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings"
	if policy {
		claimed, startedKey, receiptKey, path = state.PolicyStartedAt, bootstrapCopyPolicyStartedAnnotation, bootstrapCopyPolicyAnnotation, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies"
	}
	fresh := claimed == nil
	if fresh {
		at := time.Now().UTC().Truncate(time.Microsecond)
		var err error
		m, err = s.copyAnnotationMode(ctx, m, startedKey, at.Format(time.RFC3339Nano), false, true)
		// Unknown CAS never permits CREATE. A restart sees the retained claim and
		// may only look up the original fixed policy/binding body and identity.
		if err != nil {
			return err
		}
	}
	raw, err := s.get(ctx, path+"/"+bootstrapObjectMetadata(want).Name)
	if apierrors.IsNotFound(err) && fresh {
		if err = s.current(ctx); err != nil {
			return err
		}
		raw, err = s.api.Post().AbsPath(path).Param("fieldValidation", "Strict").Body(want).MaxRetries(0).DoRaw(ctx)
		if err != nil {
			raw, err = s.get(ctx, path+"/"+bootstrapObjectMetadata(want).Name)
		}
	} else if err == nil && fresh {
		return cfg.ErrChanged
	}
	if err != nil {
		return cfg.ErrUnavailable
	}
	got := bootstrapEmptyObject(want)
	if strictGuardJSON(raw, got) != nil || !bootstrapObjectMatches(want, got) {
		return cfg.ErrChanged
	}
	if v, ok := got.(*admission.ValidatingAdmissionPolicy); ok {
		if v.Generation != 1 {
			return cfg.ErrChanged
		}
		if v.Status.ObservedGeneration != 1 || v.Status.TypeChecking == nil {
			return ErrInitialPreparationPolicyPending
		}
		if len(v.Status.TypeChecking.ExpressionWarnings) != 0 {
			return cfg.ErrChanged
		}
	}
	md := bootstrapObjectMetadata(got)
	receipt := contracts.InitialBootstrapCopyReceipt{UID: string(md.UID), ResourceVersion: md.ResourceVersion, ObservedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if !bootstrapCopyReceiptValid(state.Claim, receipt, "") {
		return cfg.ErrUnavailable
	}
	body, _ := json.Marshal(receipt)
	_, err = s.copyAnnotation(ctx, m, receiptKey, string(body), false)
	return err
}

// Managed copies keep the producer's original installation/request annotations.
// Verify that exact provenance from the retained closure claim; accepting only
// the copy UID while discarding these fields would weaken the original scope.
func (s *InitialBootstrap) copyMetadata(ctx context.Context, claim contracts.InitialBootstrapCopyClaim, ref contracts.WorkerObjectReference, operation string, marked bool) (*meta.PartialObjectMetadata, error) {
	if !authorization.UUID(claim.InstallationID) || !authorization.UUID(claim.RequestID) || ref != claim.SQL && ref != claim.Provider {
		return nil, cfg.ErrInvalid
	}
	raw, err := s.api.Get().AbsPath("/api/v1/namespaces/"+s.desired.BootstrapNamespace+"/secrets/"+ref.Name).SetHeader("Accept", bootstrapPartialMetadataAccept).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return nil, err
	}
	var m meta.PartialObjectMetadata
	if permissionJSON(raw, 8192, 4096) != nil || strictGuardJSON(raw, &m) != nil || m.Kind != "PartialObjectMetadata" || m.APIVersion != "meta.k8s.io/v1" || m.Name != ref.Name || m.Namespace != s.desired.BootstrapNamespace || string(m.UID) != ref.UID || !identity.Text(m.ResourceVersion, 128) || m.DeletionTimestamp != nil || len(m.OwnerReferences) != 0 || len(m.Finalizers) != 0 || len(m.Labels) != 0 || m.Annotations[initialBootstrapAnnotation] != bootstrapDigest(s.desired) || m.Annotations[initialNamespaceInstallationAnnotation] != claim.InstallationID || m.Annotations[initialNamespaceRequestAnnotation] != claim.RequestID || ctx.Err() != nil {
		return nil, cfg.ErrChanged
	}
	for k := range m.Annotations {
		if k != initialBootstrapAnnotation && k != initialNamespaceInstallationAnnotation && k != initialNamespaceRequestAnnotation && k != "asservat.io/bootstrap-operation-id" && k != bootstrapCopyObjectAnnotation {
			return nil, cfg.ErrChanged
		}
	}
	if !authorization.UUID(m.Annotations["asservat.io/bootstrap-operation-id"]) {
		return nil, cfg.ErrChanged
	}
	mark := m.Annotations[bootstrapCopyObjectAnnotation]
	if marked && mark != operation || !marked && mark != "" {
		return nil, cfg.ErrChanged
	}
	return &m, nil
}
func (s *InitialBootstrap) advanceCopyDelete(ctx context.Context, seed *meta.PartialObjectMetadata, state *InitialBootstrapCopyState, ref contracts.WorkerObjectReference, marked *contracts.InitialBootstrapCopyReceipt, markedKey, removedKey string) error {
	if marked == nil {
		// If the annotation response was lost, the exact original operation mark
		// may already exist. It authorizes no deletion until its UID/RV is retained.
		m, err := s.copyMetadata(ctx, state.Claim, ref, state.Claim.OperationID, true)
		if err != nil {
			m, err = s.copyMetadata(ctx, state.Claim, ref, "", false)
			if err != nil {
				return err
			}
			patch := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": ref.UID}, {"op": "test", "path": "/metadata/resourceVersion", "value": m.ResourceVersion}, {"op": "add", "path": "/metadata/annotations/" + strings.ReplaceAll(bootstrapCopyObjectAnnotation, "/", "~1"), "value": state.Claim.OperationID}}
			body, _ := json.Marshal(patch)
			raw, _ := s.api.Patch(types.JSONPatchType).AbsPath("/api/v1/namespaces/"+s.desired.BootstrapNamespace+"/secrets/"+ref.Name).SetHeader("Accept", bootstrapPartialMetadataAccept).Param("fieldValidation", "Strict").Body(body).MaxRetries(0).DoRaw(ctx)
			clear(raw)
			m, err = s.copyMetadata(ctx, state.Claim, ref, state.Claim.OperationID, true)
			if err != nil {
				return err
			}
		}
		receipt := contracts.InitialBootstrapCopyReceipt{UID: ref.UID, ResourceVersion: m.ResourceVersion, ObservedAt: time.Now().UTC().Truncate(time.Microsecond)}
		if !bootstrapCopyReceiptValid(state.Claim, receipt, ref.UID) {
			return cfg.ErrUnavailable
		}
		body, _ := json.Marshal(receipt)
		_, err = s.copyAnnotation(ctx, seed, markedKey, string(body), false)
		return err
	}
	m, err := s.copyMetadata(ctx, state.Claim, ref, state.Claim.OperationID, true)
	if err == nil {
		if m.ResourceVersion != marked.ResourceVersion {
			return cfg.ErrChanged
		}
		options := meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &m.UID, ResourceVersion: &m.ResourceVersion}}
		raw, _ := s.api.Delete().AbsPath("/api/v1/namespaces/" + s.desired.BootstrapNamespace + "/secrets/" + ref.Name).Body(&options).MaxRetries(0).DoRaw(ctx)
		clear(raw)
		_, err = s.copyMetadata(ctx, state.Claim, ref, state.Claim.OperationID, true)
	}
	if !apierrors.IsNotFound(err) {
		return cfg.ErrUnavailable
	}
	receipt := *marked
	receipt.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	if !bootstrapCopyReceiptValid(state.Claim, receipt, ref.UID) {
		return cfg.ErrUnavailable
	}
	body, _ := json.Marshal(receipt)
	_, err = s.copyAnnotation(ctx, seed, removedKey, string(body), false)
	return err
}
