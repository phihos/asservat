package bootstrap

import (
	"context"
	"time"

	captureapp "asservat.local/asservat/internal/application/capture"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/contextstart"
)

type RegionalSourceDispatch struct {
	Router *contextstart.Router
	Signer fleetapp.SourceWorkSigner
	Now    func() time.Time
}

var _ captureapp.PolicySourceDispatcher = RegionalSourceDispatch{}

func (d RegionalSourceDispatch) DispatchSource(ctx context.Context, target targets.PodResolution, node targets.PacketSourceObservation, source collector.PacketSource) (err error) {
	if ctx == nil || ctx.Err() != nil || d.Router == nil || d.Signer == nil || d.Now == nil || !source.Permit.Dispatchable(d.Now()) {
		return fleet.ErrUnavailable
	}
	call, cancel := context.WithDeadline(ctx, source.Permit.DispatchUntil)
	defer cancel()
	// step names the bounded dispatch step for content-free failure counters.
	step := "attach"
	defer func() {
		if err != nil {
			if call.Err() != nil {
				step += "-late"
			}
			err = captureapp.StagedSourceError("dispatch-"+step, err)
		}
	}()
	a, err := d.Router.Attach(call, target.Request.ClusterID, source.Permit.Binding.SourceID)
	if err != nil {
		return err
	}
	defer a.Close()
	step = "receiver"
	r, err := a.Receiver(call)
	if err != nil {
		return err
	}
	step = "work"
	w := fleetapp.SourceWork{Channel: r.Channel, Target: target, Node: node, Source: source}
	w.NotAfter = contextstart.SourceWorkEnd(w, r)
	if !w.Valid(d.Now()) {
		return fleet.ErrUnavailable
	}
	bounded, end := context.WithDeadline(call, w.NotAfter)
	defer end()
	step = "sign"
	signed, err := d.Signer.SignSourceWork(bounded, w)
	if err != nil {
		return err
	}
	defer clear(signed)
	if bounded.Err() != nil || !w.Valid(d.Now()) {
		return fleet.ErrUnavailable
	}
	step = "run"
	return a.RunSource(bounded, w, signed)
}

func (d RegionalSourceDispatch) StopSource(ctx context.Context, cluster string, binding collector.SourceBinding) error {
	if ctx == nil || ctx.Err() != nil || d.Router == nil || d.Signer == nil || d.Now == nil || !binding.Valid() {
		return fleet.ErrUnavailable
	}
	issued := d.Now().UTC()
	call, cancel := context.WithDeadline(ctx, issued.Add(5*time.Second))
	defer cancel()
	a, err := d.Router.Attach(call, cluster, binding.SourceID)
	if err != nil {
		return err
	}
	defer a.Close()
	r, err := a.Receiver(call)
	if err != nil {
		return err
	}
	w := fleetapp.SourceWork{Channel: r.Channel, Stop: true, StopIssuedAt: issued, Source: collector.PacketSource{Permit: collector.SourcePermit{Binding: binding}}, NotAfter: identity.Earlier(issued.Add(5*time.Second), r.ValidUntil)}
	if end, ok := call.Deadline(); ok {
		w.NotAfter = identity.Earlier(w.NotAfter, end)
	}
	if !w.Valid(d.Now()) {
		return fleet.ErrUnavailable
	}
	bounded, end := context.WithDeadline(call, w.NotAfter)
	defer end()
	signed, err := d.Signer.SignSourceWork(bounded, w)
	if err != nil {
		return err
	}
	defer clear(signed)
	if bounded.Err() != nil || !w.Valid(d.Now()) {
		return fleet.ErrUnavailable
	}
	return a.RunSource(bounded, w, signed)
}

// CancelSourceSnapshot is restrictive control of an already admitted copy. It
// never refreshes source authority or requires a still-renewable source leaf.
func (d RegionalSourceDispatch) CancelSourceSnapshot(ctx context.Context, cluster string, snapshot collector.SourceSnapshot) error {
	if ctx == nil || ctx.Err() != nil || d.Router == nil || d.Signer == nil || d.Now == nil || !snapshot.Valid() {
		return fleet.ErrUnavailable
	}
	issued := d.Now().UTC()
	call, cancel := context.WithDeadline(ctx, issued.Add(5*time.Second))
	defer cancel()
	a, err := d.Router.Attach(call, cluster, snapshot.CaptureID)
	if err != nil {
		return err
	}
	defer a.Close()
	receiver, err := a.Receiver(call)
	if err != nil {
		return err
	}
	work := fleetapp.SourceWork{Channel: receiver.Channel, StopSnapshot: &snapshot, StopIssuedAt: issued, NotAfter: identity.Earlier(issued.Add(5*time.Second), receiver.ValidUntil)}
	if end, ok := call.Deadline(); ok {
		work.NotAfter = identity.Earlier(work.NotAfter, end)
	}
	if !work.Valid(d.Now()) {
		return fleet.ErrUnavailable
	}
	bounded, end := context.WithDeadline(call, work.NotAfter)
	defer end()
	signed, err := d.Signer.SignSourceWork(bounded, work)
	if err != nil {
		return err
	}
	defer clear(signed)
	if bounded.Err() != nil || !work.Valid(d.Now()) {
		return fleet.ErrUnavailable
	}
	return a.RunSource(bounded, work, signed)
}
