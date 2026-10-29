package fleet

import (
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"time"
)

type SourceWorkSigner interface {
	SignSourceWork(context.Context, SourceWork) ([]byte, error)
}
type SourceWorkVerifier interface {
	VerifySourceWork(context.Context, []byte, value.APIContextReceiver) (AuthenticatedSourceWork, error)
}

// SourceWork is a committed ordinary ongoing source purpose over one retained
// connector conversation. It has no capture, occurrence, evidence or raw grant.
type SourceWork struct {
	Channel      value.APIContextChannel
	Target       targets.PodResolution
	Node         targets.PacketSourceObservation
	Source       collector.PacketSource
	NotAfter     time.Time
	Stop         bool
	StopIssuedAt time.Time
}

func (w SourceWork) Valid(now time.Time) bool {
	p, b := w.Source.Permit, w.Source.Permit.Binding
	if w.Stop {
		p.Binding = collector.SourceBinding{}
		return w.Channel.Valid() && b.Valid() && b.RootID == w.Channel.RootID && p == (collector.SourcePermit{}) && len(w.Source.Program) == 0 && w.Source.Ring == (collector.SourceRingLimits{}) && w.Source.Resources == (collector.SourceResources{}) && w.Target == (targets.PodResolution{}) && w.Node == (targets.PacketSourceObservation{}) &&
			!w.StopIssuedAt.IsZero() && !now.Before(w.StopIssuedAt) && now.Before(w.NotAfter) && !w.NotAfter.After(w.StopIssuedAt.Add(5*time.Second))
	}
	if !w.StopIssuedAt.IsZero() {
		return false
	}
	return w.Channel.Valid() && w.Target.Valid(now) && w.Node.Valid(now) && w.Source.Valid() && p.Dispatchable(now) &&
		b.RootID == w.Channel.RootID && w.Target.Request.ClusterID == w.Channel.Connector.Binding.ClusterID && w.Target.Pin.UID == b.PodUID &&
		w.Node.PodUID == b.PodUID && w.Node.NodeUID == b.NodeUID && w.Node.BootID == b.BootID && w.Node.CollectorPodUID == b.CollectorPodUID && w.Node.CollectorEpoch == b.CollectorEpoch &&
		now.Before(w.NotAfter) && !w.NotAfter.After(p.DispatchUntil) && !w.NotAfter.After(w.Target.FreshUntil) && !w.NotAfter.After(w.Node.FreshUntil)
}
func (w SourceWork) IssuedAt() time.Time {
	if w.Stop {
		return w.StopIssuedAt
	}
	return w.Source.Permit.IssuedAt
}
func (w SourceWork) Matches(r value.APIContextReceiver, now time.Time) bool {
	return w.Valid(now) && r.Valid(now) && w.Channel == r.Channel
}

type AuthenticatedSourceWork struct {
	Work                   SourceWork
	KeyID                  string
	TrustRevision          identity.Revision
	VerifiedAt, ValidUntil time.Time
}

func (w AuthenticatedSourceWork) Valid(now time.Time) bool {
	return w.Work.Valid(now) && identity.Text(w.KeyID, 128) && w.TrustRevision.Valid() && identity.Fresh(w.VerifiedAt, w.ValidUntil, now, 5*time.Second) && !w.ValidUntil.After(w.Work.NotAfter)
}
