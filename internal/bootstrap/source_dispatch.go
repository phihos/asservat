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

// deliver signs w for the standby DeliverSource selects and sends it as one
// query. The standby keeps waiting for capture work, so source traffic never
// takes the cluster's one standby from a Save (ADR-209). step names the
// failing step for content-free counters.
func (d RegionalSourceDispatch) deliver(call context.Context, cluster string, step *string, w func(fleet.APIContextReceiver) fleetapp.SourceWork) error {
	*step = "query"
	return d.Router.DeliverSource(call, cluster, func(r fleet.APIContextReceiver) (fleetapp.SourceWork, []byte, error) {
		*step = "work"
		work := w(r)
		if end, ok := call.Deadline(); ok {
			work.NotAfter = identity.Earlier(work.NotAfter, end)
		}
		if !work.Valid(d.Now()) {
			return work, nil, fleet.ErrUnavailable
		}
		bounded, end := context.WithDeadline(call, work.NotAfter)
		defer end()
		*step = "sign"
		signed, err := d.Signer.SignSourceWork(bounded, work)
		if err == nil && (bounded.Err() != nil || !work.Valid(d.Now())) {
			clear(signed)
			err = fleet.ErrUnavailable
		}
		if err != nil {
			return work, nil, err
		}
		*step = "run"
		return work, signed, nil
	})
}

func (d RegionalSourceDispatch) DispatchSource(ctx context.Context, target targets.PodResolution, node targets.PacketSourceObservation, source collector.PacketSource) (err error) {
	if ctx == nil || ctx.Err() != nil || d.Router == nil || d.Signer == nil || d.Now == nil || !source.Permit.Dispatchable(d.Now()) {
		return fleet.ErrUnavailable
	}
	call, cancel := context.WithDeadline(ctx, source.Permit.DispatchUntil)
	defer cancel()
	step := "query"
	defer func() {
		if err != nil {
			if call.Err() != nil {
				step += "-late"
			}
			err = captureapp.StagedSourceError("dispatch-"+step, err)
		}
	}()
	return d.deliver(call, target.Request.ClusterID, &step, func(r fleet.APIContextReceiver) fleetapp.SourceWork {
		w := fleetapp.SourceWork{Channel: r.Channel, Target: target, Node: node, Source: source}
		w.NotAfter = contextstart.SourceWorkEnd(w, r)
		return w
	})
}

func (d RegionalSourceDispatch) StopSource(ctx context.Context, cluster string, binding collector.SourceBinding) error {
	if ctx == nil || ctx.Err() != nil || d.Router == nil || d.Signer == nil || d.Now == nil || !binding.Valid() {
		return fleet.ErrUnavailable
	}
	issued := d.Now().UTC()
	call, cancel := context.WithDeadline(ctx, issued.Add(5*time.Second))
	defer cancel()
	var step string
	return d.deliver(call, cluster, &step, func(r fleet.APIContextReceiver) fleetapp.SourceWork {
		return fleetapp.SourceWork{Channel: r.Channel, Stop: true, StopIssuedAt: issued, Source: collector.PacketSource{Permit: collector.SourcePermit{Binding: binding}}, NotAfter: identity.Earlier(issued.Add(5*time.Second), r.ValidUntil)}
	})
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
	var step string
	return d.deliver(call, cluster, &step, func(r fleet.APIContextReceiver) fleetapp.SourceWork {
		return fleetapp.SourceWork{Channel: r.Channel, StopSnapshot: &snapshot, StopIssuedAt: issued, NotAfter: identity.Earlier(issued.Add(5*time.Second), r.ValidUntil)}
	})
}
