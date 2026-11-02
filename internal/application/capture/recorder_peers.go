package capture

import (
	"context"
	"errors"
	"slices"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	compiler "asservat.local/asservat/internal/application/planning"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// ContextPeers resolves one action's Kubernetes packet peers in the target's
// region (ADR-283 PR 2): bounded LISTs of the target's namespace, resolved
// into frozen (UID, IP) members. The answer is an observation for review; it
// grants nothing about the peers.
type ContextPeers interface {
	ResolvePacketPeers(context.Context, targets.PeerRequest) (targets.PeerResolution, error)
}

// compileRecorderPeers compiles in; a plan with Kubernetes peers asks the
// target's region once for their resolution and compiles again with it. The
// caller has already checked current eligibility on the target, so the
// region is asked about its namespace only for an eligible caller.
func (s ContextInvestigation) compileRecorderPeers(ctx context.Context, in planning.RecorderInput) (planning.RecorderPlan, error) {
	plan, err := compiler.CompileRecorder(in, s.Filters, s.Now())
	var needed compiler.PeerResolutionNeeded
	if !errors.As(err, &needed) {
		return plan, err
	}
	if s.Peers == nil {
		return planning.RecorderPlan{}, planning.CompositionError{Code: planning.CompositionRecorderUnavailable, Path: needed.Path, Reason: "this installation cannot resolve Kubernetes peers; use cidrs entries"}
	}
	mark := time.Now()
	r, err := s.Peers.ResolvePacketPeers(ctx, needed.Request)
	auditapp.MarkStep(ctx, "p-peers", mark)
	if err != nil {
		return planning.RecorderPlan{}, compiler.PeerResolutionRefusal(needed, err)
	}
	// The hub's receipt time is the recorded generation time.
	r.ResolvedAt = s.Now().UTC().Truncate(time.Microsecond)
	if !r.Answers(needed.Request) || ctx.Err() != nil {
		return planning.RecorderPlan{}, value.ErrUnavailable
	}
	in.Peers = append(slices.Clone(in.Peers), r.Clone())
	plan, err = compiler.CompileRecorder(in, s.Filters, s.Now())
	if errors.As(err, &needed) {
		// One packet recorder per Pod: a second action is refused by the
		// composition itself; never ask the region in a loop.
		return planning.RecorderPlan{}, planning.CompositionError{Code: planning.CompositionRecorderUnavailable, Path: needed.Path, Reason: "only one packet action can select Kubernetes peers"}
	}
	return plan, err
}

// peersCurrent re-resolves the frozen Kubernetes peers of an accepted
// recorder plan at submission (ADR-283 part 3) and refuses, before
// admission reserves anything, unless the region answers exactly the
// reviewed members. The connector checks again when the node starts and
// then once per second while the recording runs.
func (s ContextInvestigation) peersCurrent(ctx context.Context, plan planning.ContextPlan) error {
	if plan.Input.Recorder == nil || len(plan.Input.Recorder.Peers) == 0 {
		return nil
	}
	rp, err := compiler.RecorderPlanForContext(plan)
	if err != nil || len(rp.Actions) != 1 {
		return value.ErrInvalid
	}
	path := "profile_composition.components[0] action " + rp.Actions[0].LocalID + ".parameters.peers"
	if s.Peers == nil {
		return planning.CompositionError{Code: planning.CompositionRecorderUnavailable, Path: path, Reason: "this installation cannot resolve Kubernetes peers; use cidrs entries"}
	}
	for _, frozen := range plan.Input.Recorder.Peers {
		mark := time.Now()
		fresh, err := s.Peers.ResolvePacketPeers(ctx, frozen.Request)
		auditapp.MarkStep(ctx, "q-peers", mark)
		switch {
		case errors.Is(err, targets.ErrPeerVerifierBusy):
			return planning.CompositionError{Code: planning.CompositionRecorderUnavailable, Path: path, Reason: "the target's cluster is already verifying its maximum number of running captures with Kubernetes peers; retry when one ends or use cidrs peers"}
		case errors.Is(err, targets.ErrPeerMissing), errors.Is(err, targets.ErrPeerLimit), errors.Is(err, targets.ErrPeerUnsupported),
			err == nil && (!fresh.Answers(frozen.Request) || !slices.Equal(fresh.Members, frozen.Members)):
			return planning.CompositionError{Code: planning.CompositionPeersChanged, Path: path, Reason: "the Kubernetes peers changed since the preview; preview again"}
		case err != nil:
			return err
		}
	}
	return ctx.Err()
}
