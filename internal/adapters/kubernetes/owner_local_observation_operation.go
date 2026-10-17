package kubernetes

import (
	"bytes"
	"context"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// OwnerLocalObservationOperationReader is the direct HWORK receiving boundary.
// It owns one native guard and the distinct installed caller pin. It cannot
// impersonate an owner client certificate or implement the general caller port.
// Original installer acceptance, current SQL and actual server TLS/key identity
// remain mandatory bootstrap dependencies.
type OwnerLocalObservationOperationReader struct {
	owner  *OwnerObservationOperationReader
	caller *ClusterObservationCallerAdmission
}

func NewOwnerLocalObservationOperationReader(c *PermissionClient, guard *OwnerWorkloadProtection, pin value.OwnerObservationPin, caller value.ClusterObservationCallerPin) (*OwnerLocalObservationOperationReader, error) {
	if !caller.Valid() || caller.RootID != pin.RootID || caller.InstallationID != pin.Pool.InstallationID || caller.ClusterID != pin.Pool.ClusterID || caller.ProtectionDigest != pin.ProtectionDigest {
		return nil, cfg.ErrInvalid
	}
	owner, err := NewOwnerObservationOperationReader(c, guard, pin)
	if err != nil {
		return nil, err
	}
	admission, err := NewClusterObservationCallerAdmission(c, owner.guard, caller)
	if err != nil {
		return nil, err
	}
	return &OwnerLocalObservationOperationReader{owner: owner, caller: admission}, nil
}

type ownerLocalCallerBoundary struct {
	reader *ClusterObservationCallerAdmission
	token  []byte
	podUID string
	first  *value.ClusterObservationCaller
}

// read performs seven real reads inside the surrounding native boundary:
// two online reviews and exact SA/Deployment/Pod/ReplicaSet/Pod. It does not
// invoke Current or manufacture a new native interval. Caller namespace and
// native guard are independently bracketed by the concrete owning operation.
func (b *ownerLocalCallerBoundary) read(ctx context.Context, start, until time.Time) (time.Time, error) {
	if b == nil || b.reader == nil || ctx == nil || ctx.Err() != nil || !b.reader.client.now().Before(until) {
		return time.Time{}, value.ErrUnavailable
	}
	name, err := b.reader.review(ctx, b.token, b.podUID)
	if err != nil {
		return time.Time{}, &observationStep{"caller-review", err}
	}
	expires, err := reviewedTokenExpiry(b.token, b.reader.client.now())
	if err != nil {
		return time.Time{}, &observationStep{"caller-token-expiry", value.ErrDenied}
	}
	until = identity.Earlier(until, expires)
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	workload, err := b.reader.liveObjects(call, name, b.podUID, true)
	if err != nil {
		return time.Time{}, &observationStep{"caller-objects", err}
	}
	again, err := b.reader.review(call, b.token, b.podUID)
	if err != nil {
		return time.Time{}, &observationStep{"caller-review-again", err}
	}
	if again != name {
		return time.Time{}, &observationStep{"caller-review-again", value.ErrDenied}
	}
	observed := value.ClusterObservationCaller{Pin: b.reader.pin, Pod: name, PodUID: b.podUID, ReplicaSet: workload.ReplicaSet, ReplicaSetUID: workload.ReplicaSetUID, WorkloadDigest: workload.Digest, ObservedAt: start, FreshUntil: until}
	if call.Err() != nil || !observed.Valid(b.reader.client.now()) || b.first != nil && !b.first.SameWorkload(observed) {
		return time.Time{}, cfg.ErrChanged
	}
	if b.first == nil {
		b.first = &observed
	}
	return identity.Earlier(until, b.first.FreshUntil), nil
}

// OwnerLocalObservationOperation is one private initial/claim/final lifetime.
// A successful claim still confers no SQL or regional metadata authority. The
// original caller token is private, bounded and cleared only after joined Close.
type OwnerLocalObservationOperation struct {
	owner             *OwnerObservationOperation
	caller            *ownerLocalCallerBoundary
	claimed, admitted bool // protected by owner.mu
	once              sync.Once
}

var _ app.OwnerNativeObservationOperation = (*OwnerLocalObservationOperation)(nil)

func (s *OwnerLocalObservationOperationReader) Begin(ctx context.Context, request value.OwnerObservationRequest, holder value.OwnerBinding, token []byte, podUID string) (*OwnerLocalObservationOperation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(podUID) || len(token) < 1 || len(token) > 16<<10 || !bytes.Equal(bytes.TrimSpace(token), token) || bytes.ContainsAny(token, " \t\r\n") {
		return nil, value.ErrInvalid
	}
	caller := &ownerLocalCallerBoundary{reader: s.caller, token: bytes.Clone(token), podUID: podUID}
	owner, err := s.owner.beginLocal(ctx, request, []value.OwnerBinding{holder}, caller)
	if err != nil {
		clear(caller.token)
		return nil, err
	}
	return &OwnerLocalObservationOperation{owner: owner, caller: caller}, nil
}

func (o *OwnerLocalObservationOperation) Original(ctx context.Context) (value.OwnerObservationNativeFacts, error) {
	if o == nil {
		return value.OwnerObservationNativeFacts{}, value.ErrInvalid
	}
	return o.owner.Original(ctx)
}

// Claim spends before I/O, rechecks actual native caller objects and online
// token status under the original guard, and never restarts that guard's age.
func (o *OwnerLocalObservationOperation) Claim(ctx context.Context, token []byte, podUID string) (time.Time, error) {
	if o == nil || ctx == nil {
		return time.Time{}, value.ErrInvalid
	}
	v := o.owner
	v.mu.Lock()
	end, finite := ctx.Deadline()
	if !finite || !v.currentLocked(ctx) || v.busy || v.final || o.claimed || podUID != o.caller.podUID || !bytes.Equal(token, o.caller.token) {
		v.closed = true
		v.cancel()
		v.mu.Unlock()
		return time.Time{}, value.ErrUnavailable
	}
	o.claimed = true
	v.busy = true
	v.reads.Add(1)
	start, until := v.original.ObservedAt, identity.Earlier(end, v.original.FreshUntil)
	v.mu.Unlock()
	defer v.reads.Done()
	call, cancel := context.WithDeadline(v.root, until)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { cancel(); close(done) })
	defer func() {
		cancel()
		if !stop() {
			<-done
		}
	}()
	ns, err := v.reader.client.namespace(call, v.reader.client.control)
	if err == nil && ns.Deleting {
		err = cfg.ErrChanged
	}
	if err == nil {
		until, err = o.caller.read(call, start, until)
	}
	bounded, finish := context.WithDeadline(call, until)
	defer finish()
	if err == nil {
		ns, err = v.reader.client.namespace(bounded, v.reader.client.control)
		if err == nil && ns.Deleting {
			err = cfg.ErrChanged
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.busy = false
	if err != nil || !v.currentLocked(ctx) || bounded.Err() != nil || !v.reader.client.now().Before(until) {
		v.closed = true
		v.cancel()
		if err != nil {
			return time.Time{}, err
		}
		return time.Time{}, value.ErrUnavailable
	}
	v.original.FreshUntil = identity.Earlier(v.original.FreshUntil, until)
	o.admitted = true
	return v.original.FreshUntil, nil
}

func (o *OwnerLocalObservationOperation) Final(ctx context.Context) (value.OwnerObservationNativeFacts, error) {
	if o == nil {
		return value.OwnerObservationNativeFacts{}, value.ErrInvalid
	}
	o.owner.mu.Lock()
	admitted := o.admitted && o.owner.currentLocked(ctx)
	if !admitted {
		o.owner.closed = true
		o.owner.cancel()
	}
	o.owner.mu.Unlock()
	if !admitted {
		return value.OwnerObservationNativeFacts{}, value.ErrUnavailable
	}
	return o.owner.Final(ctx)
}

func (o *OwnerLocalObservationOperation) Close() {
	if o == nil {
		return
	}
	o.once.Do(func() {
		o.owner.Close()
		o.owner.mu.Lock()
		clear(o.caller.token)
		o.caller.token = nil
		o.owner.mu.Unlock()
	})
}
