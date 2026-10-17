package native

import (
	"context"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// checkedNativeAdmission transfers one just-completed Check through local
// constructor/attachment validation. It is never retained by an operation,
// serialized, or reused across I/O. Public entry points always mint their own
// fresh check. The original call is retained without comparing Context values.
type checkedNativeAdmission struct {
	gate  *evidence.NativeFrameGate
	call  context.Context
	lease value.NativeLease
	used  atomic.Bool
}

func checkNativeAdmission(call context.Context, gate *evidence.NativeFrameGate) (*checkedNativeAdmission, error) {
	if gate == nil || call == nil {
		return nil, artifact.ErrInvalid
	}
	lease, err := gate.Check(call)
	if err != nil {
		return nil, err
	}
	if until, bounded := call.Deadline(); bounded && until.Before(lease.Until) {
		lease.Until = until
	}
	checked := &checkedNativeAdmission{gate: gate, call: call, lease: lease}
	if _, err = checked.restrict(gate); err != nil {
		return nil, err
	}
	return checked, nil
}

func (c *checkedNativeAdmission) take(gate *evidence.NativeFrameGate) (value.NativeLease, error) {
	if c == nil || !c.used.CompareAndSwap(false, true) {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	return c.restrict(gate)
}

// The snapshot is only a restrictive veto on the original fresh Check, never
// a source of authority. Revalidate after local validation/locks and retain the
// earliest original bound. Neither method invokes the mutable authority port.
func (c *checkedNativeAdmission) restrict(gate *evidence.NativeFrameGate) (value.NativeLease, error) {
	if c == nil || gate == nil || c.gate != gate || c.call == nil || c.call.Err() != nil || !c.lease.Valid(time.Now()) || !c.lease.Operation.CurrentValid(time.Now()) {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	current, err := gate.TerminalLease(c.call)
	if err != nil || !current.Operation.Equal(c.lease.Operation) || current.Certificate != c.lease.Certificate || current.Sequence != c.lease.Sequence {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	lease := c.lease
	if current.Until.Before(lease.Until) {
		lease.Until = current.Until
	}
	if !lease.Valid(time.Now()) || c.call.Err() != nil {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	return lease, nil
}
