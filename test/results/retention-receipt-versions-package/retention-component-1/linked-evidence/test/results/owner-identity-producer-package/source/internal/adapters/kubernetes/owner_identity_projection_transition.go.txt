package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
)

// The sole sibling-preserving owner journal writer. No resource, capacity or
// cleanup field can change here. A spent launch permanently closes projection
// mutations; launch itself has a separate exact transition predicate.
func ownerIdentityProjectionTransition(old, next contracts.InitialRuntimeResourceState) bool {
	if old.OwnerLaunch != nil || next.OwnerLaunch != nil || next.OwnerIdentity == nil {
		return false
	}
	a, b := old, next
	a.OwnerIdentity = nil
	b.OwnerIdentity = nil
	if !equalJSON(a, b) {
		return false
	}
	p, q := old.OwnerIdentity, next.OwnerIdentity
	if p == nil {
		return q.Credentials == nil && q.Configuration == nil && q.Receipt == nil
	}
	parent, nextParent := *p, *q
	parent.Credentials = nil
	parent.Configuration = nil
	parent.Receipt = nil
	nextParent.Credentials = nil
	nextParent.Configuration = nil
	nextParent.Receipt = nil
	if !equalJSON(parent, nextParent) || p.Receipt != nil {
		return false
	}
	changed := 0
	for n, pair := range [][2]*contracts.OwnerIdentityObjectAttempt{{p.Credentials, q.Credentials}, {p.Configuration, q.Configuration}} {
		before, after := pair[0], pair[1]
		if equalJSON(before, after) {
			continue
		}
		changed++
		if after == nil {
			return false
		}
		if before == nil {
			if after.Receipt != nil || n == 1 && (p.Credentials == nil || p.Credentials.Receipt == nil) {
				return false
			}
		} else {
			if before.Receipt != nil || after.Receipt == nil {
				return false
			}
			x, y := *before, *after
			x.Receipt = nil
			y.Receipt = nil
			if !equalJSON(x, y) {
				return false
			}
		}
	}
	if !equalJSON(p.Receipt, q.Receipt) {
		changed++
		if q.Receipt == nil || p.Credentials == nil || p.Credentials.Receipt == nil || p.Configuration == nil || p.Configuration.Receipt == nil {
			return false
		}
		c, f := p.Credentials.Receipt, p.Configuration.Receipt
		if q.Receipt.Credentials != c.Object || q.Receipt.CredentialsResourceVersion != c.ResourceVersion || q.Receipt.Configuration != f.Object || q.Receipt.ConfigurationResourceVersion != f.ResourceVersion {
			return false
		}
	}
	return changed == 1
}

func (s *OwnerIdentityProjection) write(ctx context.Context, old contracts.InitialRuntimeResourceSnapshot, obj *core.Secret, next contracts.InitialRuntimeResourceState, until time.Time) (contracts.InitialRuntimeResourceSnapshot, error) {
	var zero contracts.InitialRuntimeResourceSnapshot
	if !ownerIdentityProjectionTransition(old.State, next) || !s.root.resources.valid(next) || !s.root.resources.now().Before(old.State.Until) {
		return zero, cfg.ErrChanged
	}
	call, end := context.WithDeadline(ctx, until)
	defer end()
	if initialHandoverDeadline(call, s.root.resources.now, until) != nil {
		return zero, cfg.ErrUnavailable
	}
	raw, e := json.Marshal(next)
	if e != nil || len(raw) > contracts.InitialRuntimeResourcesMaxBytes {
		return zero, cfg.ErrInvalid
	}
	defer clear(raw)
	body := obj.DeepCopy()
	body.Data = map[string][]byte{"state.json": raw}
	reply, e := s.root.bridge.source.client.api.Put().AbsPath(s.root.resources.path()).Param("fieldValidation", "Strict").MaxRetries(0).Body(body).DoRaw(call)
	defer clear(reply)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	got, _, e := s.root.resources.decode(call, reply)
	if e != nil || got.UID != old.UID || got.ResourceVersion == old.ResourceVersion || !equalJSON(got.State, next) || initialHandoverDeadline(call, s.root.resources.now, until) != nil {
		return zero, cfg.ErrChanged
	}
	return got, nil
}
