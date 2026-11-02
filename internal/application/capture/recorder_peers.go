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
