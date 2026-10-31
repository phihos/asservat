package contextstart

import (
	"context"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

type SourceQueue interface {
	EnqueueSourceExpected(context.Context, targets.PacketSourceObservation, collector.PacketSource) (collector.Work, error)
	EnqueueSourceStop(context.Context, collector.SourceBinding, time.Time) (collector.Work, error)
}
type SourceLocal struct {
	Snapshots evidence.SourceSnapshotCanceller
	Verifier  app.SourceWorkVerifier
	Queue     SourceQueue
}

func sourceReply(w app.SourceWork, state string) contracts.SourceReply {
	reply := contracts.SourceReply{Format: contracts.SourceWorkFormat, SourceID: w.Binding().SourceID, Fence: w.Binding().Fence, State: state}
	if w.StopSnapshot != nil {
		reply.CaptureID = w.StopSnapshot.CaptureID
		reply.SnapshotID = w.StopSnapshot.Request.SnapshotID
	}
	return reply
}
func matchingSourceReply(w app.SourceWork, r contracts.SourceReply) bool {
	return r.SourceID == w.Binding().SourceID && r.Fence == w.Binding().Fence && (w.StopSnapshot == nil && r.CaptureID == "" && r.SnapshotID == "" || w.StopSnapshot != nil && r.CaptureID == w.StopSnapshot.CaptureID && r.SnapshotID == w.StopSnapshot.Request.SnapshotID)
}

// applySourceWork is the region's answer to one source-work query: verify
// against the current owner receiver, then queue the restrictive or arming
// effect. An effect refusal is the closed "unavailable" state, not an error.
func applySourceWork(ctx context.Context, r fleet.APIContextReceiver, signed []byte, local *SourceLocal, now func() time.Time) (contracts.SourceReply, error) {
	if local == nil || local.Verifier == nil || local.Queue == nil {
		return contracts.SourceReply{}, targets.ErrUnsupported
	}
	auth, err := local.Verifier.VerifySourceWork(ctx, signed, r)
	if err != nil || !auth.Valid(now()) {
		return contracts.SourceReply{}, targets.ErrDenied
	}
	w := auth.Work
	call, cancel := context.WithDeadline(ctx, auth.ValidUntil)
	defer cancel()
	if call.Err() != nil || !w.Valid(now()) {
		return contracts.SourceReply{}, targets.ErrUnavailable
	}
	var effectErr error
	if w.StopSnapshot != nil {
		if local.Snapshots == nil {
			effectErr = fleet.ErrUnavailable
		} else {
			effectErr = local.Snapshots.CancelSourceSnapshot(call, *w.StopSnapshot)
		}
	} else if w.Stop {
		_, effectErr = local.Queue.EnqueueSourceStop(call, w.Source.Permit.Binding, w.NotAfter)
	} else {
		_, effectErr = local.Queue.EnqueueSourceExpected(call, w.Node, w.Source)
	}
	state := "queued"
	if effectErr != nil {
		state = "unavailable"
	}
	if call.Err() != nil || !auth.Valid(now()) {
		return contracts.SourceReply{}, targets.ErrUnavailable
	}
	return sourceReply(w, state), nil
}

// DeliverSource sends one signed source work as an ADR-179 query on an idle
// standby, which keeps waiting for capture work afterwards. Source arms,
// renewals and stops therefore never consume the cluster's one standby
// (ADR-209) that Saves and other context starts attach to. sign receives the
// selected standby's current receiver, since the work binds its channel.
func (r *Router) DeliverSource(ctx context.Context, cluster string, sign func(fleet.APIContextReceiver) (app.SourceWork, []byte, error)) error {
	if r == nil || sign == nil {
		return fleet.ErrInvalid
	}
	var w app.SourceWork
	var reply contracts.SourceReply
	_, err := r.Query(ctx, cluster, querySourceWork, receiverBody(func(current fleet.APIContextReceiver) (any, error) {
		var signed []byte
		var e error
		w, signed, e = sign(current)
		return signed, e
	}), &reply)
	if err != nil {
		return err
	}
	if !matchingSourceReply(w, reply) || reply.State != "queued" && reply.State != "unavailable" {
		return contracts.ErrAPIContextProtocol
	}
	if reply.State != "queued" {
		return fleet.ErrUnavailable
	}
	return nil
}

// SourceWorkEnd retains all original precommit/target/receiver bounds, while
// the separate active leaf remains within its committed thirty-second limit.
func SourceWorkEnd(w app.SourceWork, r fleet.APIContextReceiver) time.Time {
	return identity.Earlier(w.Source.Permit.DispatchUntil, identity.Earlier(w.Target.FreshUntil, identity.Earlier(w.Node.FreshUntil, r.ValidUntil)))
}
