package kubernetes

import (
	"encoding/json"
	"reflect"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
)

// These private journal operations are bracketed by Publish's explicit current
// checks. They do not recursively acquire another enforcement proof.
func (o *publicProjectionOperation) read() (contracts.PublicRuntimeRoleSnapshot, *core.Secret, error) {
	var zero contracts.PublicRuntimeRoleSnapshot
	if err := o.live(); err != nil {
		return zero, nil, err
	}
	s := o.root
	raw, err := s.client.api.Get().AbsPath(s.path() + "/" + s.name()).MaxRetries(0).DoRaw(o.ctx)
	defer clear(raw)
	if err != nil {
		return zero, nil, o.fail(err)
	}
	v, obj, err := s.decode(raw, o.started, o.until)
	if err != nil {
		return zero, nil, o.fail(err)
	}
	o.restrict(v.State.Until)
	v.ValidUntil = o.until
	if err = o.live(); err != nil {
		return zero, nil, err
	}
	return v, obj, nil
}
func (o *publicProjectionOperation) update(old contracts.PublicRuntimeRoleSnapshot, object *core.Secret, next contracts.PublicRuntimeRoleState) (contracts.PublicRuntimeRoleSnapshot, error) {
	var zero contracts.PublicRuntimeRoleSnapshot
	if err := o.live(); err != nil {
		return zero, err
	}
	s := o.root
	if !runtimeRoleStateValid(s.input, next, s.client.now()) {
		return zero, o.fail(cfg.ErrChanged)
	}
	b, err := json.Marshal(next)
	if err != nil || len(b) > contracts.PublicRuntimeRoleMaxBytes {
		return zero, o.fail(cfg.ErrUnavailable)
	}
	defer clear(b)
	object = object.DeepCopy()
	object.Data = map[string][]byte{"state.json": b}
	raw, err := s.client.api.Put().AbsPath(s.path()+"/"+s.name()).Param("fieldValidation", "Strict").Body(object).MaxRetries(0).DoRaw(o.ctx)
	defer clear(raw)
	// Unknown CAS never acknowledges the first claim; no lookup can make it fresh.
	if err != nil {
		return zero, o.fail(err)
	}
	if err = o.live(); err != nil {
		return zero, err
	}
	v, _, err := s.decode(raw, old.ObservedAt, o.until)
	if err != nil {
		return zero, o.fail(err)
	}
	if v.UID != old.UID || v.ResourceVersion == old.ResourceVersion || !reflect.DeepEqual(v.State, next) {
		return zero, o.fail(cfg.ErrChanged)
	}
	return v, nil
}
