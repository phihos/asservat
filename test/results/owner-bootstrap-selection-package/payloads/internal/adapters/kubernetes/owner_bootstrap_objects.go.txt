package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func (p *ownerBootstrapPhase) objectBody() (*core.ConfigMap, error) {
	root := p.producer.root
	claim := p.snapshot.State.OwnerBootstrap
	if claim == nil || claim.Child == nil || !ownerBootstrapBodyBound(root, claim, p.body) {
		return nil, cfg.ErrChanged
	}
	raw, err := json.Marshal(p.body)
	if err != nil || len(raw) > contracts.OwnerDeploymentMaxBytes {
		return nil, cfg.ErrInvalid
	}
	return &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: contracts.OwnerBootstrapSelectionName(root.input.InstallationID), Namespace: root.input.Namespace.Name, Annotations: map[string]string{
		"asservat.io/owner-bootstrap-root": p.snapshot.UID, "asservat.io/owner-bootstrap-setup": p.snapshot.State.SetupID,
		"asservat.io/owner-bootstrap-selection": claim.OperationID, "asservat.io/owner-bootstrap-create": claim.Child.OperationID, "asservat.io/owner-bootstrap-digest": claim.PublicDigest,
	}}, Immutable: ptr.To(true), Data: map[string]string{contracts.OwnerBootstrapSelectionFile: string(raw)}}, nil
}
func (p *ownerBootstrapPhase) createChild(ctx context.Context) error {
	root := p.producer.root
	claim := p.snapshot.State.OwnerBootstrap
	if claim == nil || claim.Child == nil || claim.Child.Receipt != nil || initialHandoverDeadline(ctx, root.resources.now, claim.Child.Until) != nil {
		return cfg.ErrUnavailable
	}
	body, err := p.objectBody()
	if err != nil {
		return err
	}
	reply, err := root.bridge.source.client.api.Post().AbsPath("/api/v1/namespaces/"+body.Namespace+"/configmaps").Param("fieldValidation", "Strict").MaxRetries(0).Body(body).DoRaw(ctx)
	if err != nil {
		return cfg.ErrUnavailable
	}
	if _, err = p.verifyChild(ctx, reply); err != nil {
		return err
	}
	return initialHandoverDeadline(ctx, root.resources.now, claim.Child.Until)
}
func (p *ownerBootstrapPhase) readChild(ctx context.Context) (contracts.OwnerBootstrapObjectReceipt, error) {
	var zero contracts.OwnerBootstrapObjectReceipt
	body, err := p.objectBody()
	if err != nil {
		return zero, err
	}
	raw, err := p.producer.root.bridge.source.client.api.Get().AbsPath("/api/v1/namespaces/" + body.Namespace + "/configmaps/" + body.Name).MaxRetries(0).DoRaw(ctx)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	return p.verifyChild(ctx, raw)
}
func (p *ownerBootstrapPhase) verifyChild(ctx context.Context, raw []byte) (contracts.OwnerBootstrapObjectReceipt, error) {
	var zero contracts.OwnerBootstrapObjectReceipt
	want, err := p.objectBody()
	if err != nil {
		return zero, err
	}
	var actual core.ConfigMap
	if permissionJSON(raw, contracts.OwnerDeploymentMaxBytes*2, 131072) != nil || strictGuardJSON(raw, &actual) != nil || actual.APIVersion != "v1" || actual.Kind != "ConfigMap" ||
		!authorization.UUID(string(actual.UID)) || !ownerMetadata(actual.ObjectMeta, want.Namespace, want.Name, string(actual.UID)) || actual.Immutable == nil || !*actual.Immutable ||
		len(actual.BinaryData) != 0 || len(actual.OwnerReferences) != 0 || len(actual.Finalizers) != 0 || len(actual.Labels) != 0 ||
		!equalJSON(actual.Annotations, want.Annotations) || !equalJSON(actual.Data, want.Data) {
		return zero, cfg.ErrChanged
	}
	now := p.producer.root.resources.now().UTC().Truncate(time.Microsecond)
	receipt := contracts.OwnerBootstrapObjectReceipt{Object: contracts.WorkerObjectReference{Name: actual.Name, UID: string(actual.UID)}, ResourceVersion: actual.ResourceVersion, ObservedAt: now}
	claim := p.snapshot.State.OwnerBootstrap
	if observed := p.producer.observedChild; observed != nil && (observed.Object != receipt.Object || observed.ResourceVersion != receipt.ResourceVersion) {
		return zero, cfg.ErrChanged
	}
	if old := claim.Child.Receipt; old != nil {
		if old.Object != receipt.Object || old.ResourceVersion != receipt.ResourceVersion {
			return zero, cfg.ErrChanged
		}
		receipt = *old
	}
	next := p.snapshot.State
	parent := *claim
	child := *claim.Child
	parent.Child = &child
	child.Receipt = &receipt
	next.OwnerBootstrap = &parent
	if !ownerBootstrapStateValid(p.producer.root.input.InstallationID, next, now) || initialHandoverDeadline(ctx, p.producer.root.resources.now, p.until) != nil {
		return zero, cfg.ErrChanged
	}
	if p.producer.observedChild == nil {
		observed := receipt
		p.producer.observedChild = &observed
	}
	return receipt, nil
}
func (p *ownerBootstrapPhase) write(ctx context.Context, next contracts.InitialRuntimeResourceState, end time.Time) error {
	root := p.producer.root
	old := p.snapshot
	if !ownerBootstrapTransition(old.State, next) || p.object == nil || string(p.object.UID) != old.UID || p.object.ResourceVersion != old.ResourceVersion || !root.resources.valid(next) || !root.resources.now().Before(old.State.Until) {
		return cfg.ErrChanged
	}
	end = identity.Earlier(end, identity.Earlier(p.until, old.State.Until))
	call, stop := context.WithDeadline(ctx, end)
	defer stop()
	if initialHandoverDeadline(call, root.resources.now, end) != nil {
		return cfg.ErrUnavailable
	}
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > contracts.InitialRuntimeResourcesMaxBytes {
		return cfg.ErrInvalid
	}
	defer clear(raw)
	body := p.object.DeepCopy()
	body.Data = map[string][]byte{"state.json": raw}
	reply, err := root.bridge.source.client.api.Put().AbsPath(root.resources.path()).Param("fieldValidation", "Strict").MaxRetries(0).Body(body).DoRaw(call)
	defer clear(reply)
	if err != nil {
		return cfg.ErrUnavailable
	}
	got, object, err := root.resources.decode(call, reply)
	if err != nil || got.UID != old.UID || got.ResourceVersion == old.ResourceVersion || !equalJSON(got.State, next) || initialHandoverDeadline(call, root.resources.now, end) != nil {
		return cfg.ErrChanged
	}
	p.until = identity.Earlier(p.until, end)
	got.ValidUntil = identity.Earlier(got.ValidUntil, p.until)
	p.snapshot, p.object = got, object
	return nil
}
