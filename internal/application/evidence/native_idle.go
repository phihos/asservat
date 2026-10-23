package evidence

import (
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// NativeNoOperation is a successful private SQL absence/closed observation,
// never a conversion of a timeout, denied lookup, expired active row or 404.
// It is insufficient for an idle wire response until the live Pod proof matches.
type NativeNoOperation struct {
	Worker value.AcquisitionWorkerIdentity
}

func (*NativeNoOperation) Error() string { return "no native operation is currently dispatchable" }

type NativeIdle struct {
	Worker            value.AcquisitionWorkerIdentity
	Proof             value.AcquisitionPeerProof
	ObservedAt, Until time.Time
}

func (*NativeIdle) Error() string { return "no native command admitted" }
func (i *NativeIdle) Valid(now time.Time) bool {
	return i != nil && i.Worker.Valid(now) && i.Proof.Valid(now) && i.Worker.Worker.Binding == i.Proof.Binding && identity.Fresh(i.ObservedAt, i.Until, now, 5*time.Second) && !i.Until.After(i.Worker.FreshUntil) && !i.Until.After(i.Proof.FreshUntil)
}
