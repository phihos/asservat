package contextstart

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// ADR-179 pre-work target queries. The hub asks on an idle standby; the region
// answers while it still waits for work, so a query never consumes the
// standby. Queries are not operations: no work is verified or executed.
const (
	queryResolveWorkload         = "resolve-workload"
	queryResolveWorkloadIdentity = "resolve-workload-identity"
	queryResolvePod              = "resolve-pod"
	// ADR-228: one bounded Pod LIST of a named workload's restart counters,
	// plus one Event LIST of its namespace for a probe detector (ADR-230).
	queryObserveRestarts = "observe-workload-restarts"
	// ADR-245: one decision-time SubjectAccessReview of one principal for one
	// exact Pod by the target cluster's connector.
	queryReviewAccess = "review-access"
	// ADR-248: whether the target Pod's node collector offers the packet
	// recorder now.
	queryPacketRecorder          = "packet-recorder"
	queryResolvePacketRecorder   = "resolve-packet-recorder"
	queryResolveOngoingRecorders = "resolve-ongoing-recorders"
)

// RecorderTargets is the region's optional packet recorder availability
// (ADR-248). A region without it answers the query as unsupported, which
// keeps every composition plan-only.
type RecorderTargets interface {
	PacketRecorder(context.Context, targets.RecorderRequest) (targets.RecorderAnswer, error)
}

// ReviewTargets is the region's optional decision-time access review
// (ADR-245). A region without it answers the query as unsupported, which
// grants nothing.
type ReviewTargets interface {
	ReviewAccess(context.Context, targets.AccessReviewRequest) (targets.AccessReviewAnswer, error)
}

// PacketTargetResolver composes exact target and recorder readiness. A region
// without this query capability returns a closed unsupported reply.
type PacketTargetResolver interface {
	ResolvePacketRecorder(context.Context, targets.Request) (targets.RecorderResolution, error)
}

type OngoingTargetResolver interface {
	ResolveOngoingRecorders(context.Context, []targets.OngoingRecorderRequest) ([]targets.OngoingRecorderResolution, error)
}

// RestartTargets is the region's optional restart observation (ADR-228). A
// region without it answers the query as unsupported.
type RestartTargets interface {
	ObserveWorkloadRestarts(context.Context, targets.RestartRequest) (targets.RestartObservation, error)
}

// WorkloadIdentityTargets is metadata-only and does not require a live Pod.
// Older resolvers return unsupported; the caller must not select a replacement.
type WorkloadIdentityTargets interface {
	ResolveWorkloadIdentity(context.Context, targets.WorkloadRequest) (targets.WorkloadIdentityResolution, error)
}

// QueryTargets is the region's own cluster target resolver.
type QueryTargets interface {
	ResolveWorkload(context.Context, targets.WorkloadRequest) (targets.PodResolution, error)
	ResolvePod(context.Context, targets.Request) (targets.PodResolution, error)
}

// answerReporter optionally receives the region's fixed answer step
// durations; it never sees targets, peers or error text.
type answerReporter interface{ ReportAnswer(string) }

// Closed failure labels; raw errors never cross the exchange.
var queryFailures = []struct {
	label string
	err   error
}{
	{"changed", targets.ErrChanged},
	{"denied", targets.ErrDenied},
	{"invalid", targets.ErrInvalid},
	{"unscheduled", targets.ErrUnscheduled},
	{"unsupported", targets.ErrUnsupported},
	{"unavailable", targets.ErrUnavailable},
}

func queryFailureLabel(err error) string {
	for _, f := range queryFailures {
		if errors.Is(err, f.err) {
			return f.label
		}
	}
	return "unavailable"
}
func queryFailureError(label string) error {
	for _, f := range queryFailures {
		if f.label == label {
			return f.err
		}
	}
	return targets.ErrUnavailable
}

// errQueryAnswer marks a closed regional answer; the exchange stays usable.
type errQueryAnswer struct{ err error }

func (e errQueryAnswer) Error() string { return e.err.Error() }
func (e errQueryAnswer) Unwrap() error { return e.err }

// nextQuery reserves the next query sequence before any I/O.
func (s *frameStream) nextQuery() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.querySeq + 1
	if s.closed || next > contracts.APIContextMaximumQueries {
		return 0, contracts.ErrAPIContextProtocol
	}
	s.querySeq = next
	return next, nil
}

// query is the hub's question to the region. It returns the region receiver's
// validity, checked after a fresh source pull, bounding this exchange's I/O
// and completion. Authority-bearing answers remain bounded by it. Completed
// API target metadata keeps its own original observation interval (ADR-260).
// Any error other than errQueryAnswer leaves the stream unusable.
func (s *frameStream) query(ctx context.Context, method string, in, out any) (time.Time, error) {
	if s == nil || ctx == nil || s.sources == nil {
		return time.Time{}, fleet.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	seq, e := s.nextQuery()
	if e != nil {
		return time.Time{}, e
	}
	body, e := json.Marshal(in)
	if e != nil {
		return time.Time{}, fleet.ErrInvalid
	}
	payload, e := contracts.EncodeAPIContextOperation(contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: seq, Method: method, Body: body})
	if e != nil {
		return time.Time{}, e
	}
	defer clear(payload)
	defer markQuery(ctx, "q-total", time.Now())
	pulled := time.Now()
	if e = s.pullSource(call); e != nil {
		s.record(streamHubQuerySource, streamErrorReason(e))
		return time.Time{}, fleet.ErrUnavailable
	}
	markQuery(ctx, "q-source", pulled)
	checked := time.Now()
	receiver, e := s.check(call)
	markQuery(ctx, "q-check", checked)
	if e != nil || !receiver.Valid(time.Now()) || receiver.Channel != s.channel {
		s.record(streamHubQueryCheck, queryCheckReason(e))
		s.interruptAt(streamSendPeer, streamPeerInvalid)
		return time.Time{}, fleet.ErrUnavailable
	}
	sentUntil, e := s.send(call, contracts.APIContextFrame{Kind: contracts.APIContextQueryFrame, Payload: payload})
	if e != nil {
		return time.Time{}, e
	}
	answered := time.Now()
	f, receivedUntil, e := s.receive(call)
	markQuery(ctx, "q-answer", answered)
	if e != nil {
		// The sent query is now unanswered; a caller cancelled before receive
		// began is only recorded there, so close the stream here.
		s.interruptAt(streamReceiveCall, streamErrorReason(e))
		return time.Time{}, e
	}
	defer clear(f.Payload)
	reply, e := contracts.DecodeAPIContextOperationReply(f.Payload)
	if f.Kind != contracts.APIContextAnswerFrame || e != nil || reply.Sequence != seq || reply.Method != method || (reply.Failure == "") == (len(reply.Body) == 0) {
		s.interruptAt(streamReceiveResult, streamProtocol)
		return time.Time{}, contracts.ErrAPIContextProtocol
	}
	var answerError error
	if reply.Failure != "" {
		for _, failure := range queryFailures {
			if reply.Failure == failure.label {
				answerError = errQueryAnswer{failure.err}
				break
			}
		}
	}
	if reply.Failure != "" && answerError == nil || reply.Failure == "" && decodeOperationBody(reply.Body, out) != nil {
		s.interruptAt(streamReceiveResult, streamProtocol)
		return time.Time{}, contracts.ErrAPIContextProtocol
	}
	// Both finite frame calls have joined. A matched answer also acknowledges
	// the outbound query; only now can either hub socket timer leave this phase.
	until := identity.Earlier(receiver.ValidUntil, identity.Earlier(sentUntil, receivedUntil))
	if e := s.completeQuery(call, until); e != nil {
		return time.Time{}, e
	}
	if answerError != nil {
		return time.Time{}, answerError
	}
	return until, nil
}

// completeQuery returns a semantically acknowledged hub query to the exact
// original passive residence. It renews no answer, caller or work authority.
// Holding mu excludes new logical frame/source I/O across both deadline hooks.
// The sole bounded background reader remains active to detect EOF.
func (s *frameStream) completeQuery(ctx context.Context, until time.Time) error {
	s.mu.Lock()
	passiveUntil, bounded := s.ctx.Deadline()
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	live := func() bool {
		now := time.Now()
		return bounded && s.sources != nil && !s.closed && s.first.Load() == nil &&
			!s.leaseStarted && s.reads == 0 && s.writes == 0 &&
			ctx.Err() == nil && s.ctx.Err() == nil &&
			now.Before(until) && now.Before(passiveUntil)
	}
	stage, reason := streamReceiveResult, streamUnavailable
	ok := live()
	if ok {
		stage = streamReceiveDeadline
		if e := s.readDeadline(passiveUntil); e != nil {
			ok, reason = false, streamErrorReason(e)
		} else {
			ok = live()
		}
	}
	if ok {
		stage = streamSendDeadline
		if e := s.writeDeadline(passiveUntil); e != nil {
			ok, reason = false, streamErrorReason(e)
		} else {
			ok = live()
		}
	}
	if !ok {
		// Mark terminal while still owning admission, including when a deadline
		// hook fails or cancellation races the transition. Never revive a stream.
		s.closed = true
		s.cancel()
	}
	s.mu.Unlock()
	if !ok {
		s.interruptAt(stage, reason)
		return fleet.ErrUnavailable
	}
	return nil
}

// answerQuery is the region's reply to one hub query while awaiting work. The
// hub owner must be current before this region discloses any target fact.
func (s *frameStream) answerQuery(ctx context.Context, f contracts.APIContextFrame) error {
	if s.targets == nil {
		return contracts.ErrAPIContextProtocol
	}
	q, e := contracts.DecodeAPIContextOperation(f.Payload)
	if e != nil {
		return e
	}
	seq, e := s.nextQuery()
	if e != nil || q.Sequence != seq {
		return contracts.ErrAPIContextProtocol
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if r, ok := s.targets.(answerReporter); ok {
		var times *auditapp.StepTimes
		call, times = auditapp.WithStepTimes(call)
		defer func() { r.ReportAnswer(times.String()) }()
	}
	checked := time.Now()
	owner, e := s.check(call)
	auditapp.MarkStep(call, "r-check", checked)
	if e != nil || !owner.Valid(time.Now()) || owner.Channel != s.channel {
		stage := streamRegionalQueryOwner
		var step interface{ ReceiverCheckStep() string }
		if errors.As(e, &step) {
			switch step.ReceiverCheckStep() {
			case "local":
				stage = streamRegionalQueryLocal
			case "owner":
				stage = streamRegionalQueryOwnerAuth
			}
		}
		s.record(stage, queryCheckReason(e))
		return fleet.ErrUnavailable
	}
	until, _ := call.Deadline()
	bounded, stop := context.WithDeadline(call, identity.Earlier(until, owner.ValidUntil))
	defer stop()
	var out any
	resolved := time.Now()
	switch q.Method {
	case queryResolveWorkloadIdentity:
		var r targets.WorkloadRequest
		if decodeOperationBody(q.Body, &r) != nil || !r.Valid() {
			return contracts.ErrAPIContextProtocol
		}
		if resolver, ok := s.targets.(WorkloadIdentityTargets); ok {
			out, e = resolver.ResolveWorkloadIdentity(bounded, r)
		} else {
			e = targets.ErrUnsupported
		}
	case queryResolveWorkload:
		var r targets.WorkloadRequest
		if decodeOperationBody(q.Body, &r) != nil {
			return contracts.ErrAPIContextProtocol
		}
		out, e = s.targets.ResolveWorkload(bounded, r)
	case queryResolvePod:
		var r targets.Request
		if decodeOperationBody(q.Body, &r) != nil {
			return contracts.ErrAPIContextProtocol
		}
		out, e = s.targets.ResolvePod(bounded, r)
	case queryObserveRestarts:
		var r targets.RestartRequest
		if decodeOperationBody(q.Body, &r) != nil {
			return contracts.ErrAPIContextProtocol
		}
		if observer, ok := s.targets.(RestartTargets); ok {
			out, e = observer.ObserveWorkloadRestarts(bounded, r)
		} else {
			e = targets.ErrUnsupported
		}
	case queryReviewAccess:
		var r targets.AccessReviewRequest
		if decodeOperationBody(q.Body, &r) != nil {
			return contracts.ErrAPIContextProtocol
		}
		if reviewer, ok := s.targets.(ReviewTargets); ok {
			out, e = reviewer.ReviewAccess(bounded, r)
		} else {
			e = targets.ErrUnsupported
		}
	case queryResolvePacketRecorder:
		var r targets.Request
		if decodeOperationBody(q.Body, &r) != nil || !r.Valid() {
			return contracts.ErrAPIContextProtocol
		}
		if resolver, ok := s.targets.(PacketTargetResolver); ok {
			out, e = resolver.ResolvePacketRecorder(bounded, r)
		} else {
			e = targets.ErrUnsupported
		}
	case queryPacketRecorder:
		var r targets.RecorderRequest
		if decodeOperationBody(q.Body, &r) != nil {
			return contracts.ErrAPIContextProtocol
		}
		if recorders, ok := s.targets.(RecorderTargets); ok && r.Valid() {
			out, e = recorders.PacketRecorder(bounded, r)
		} else {
			e = targets.ErrUnsupported
		}
	case queryResolveSourceSnapshots:
		var r []targets.SourceSnapshotTarget
		if decodeOperationBody(q.Body, &r) != nil || !ValidSourceSnapshotBatch(r, SourceSnapshotQueryBatchLimit) {
			return contracts.ErrAPIContextProtocol
		}
		if resolver, ok := s.targets.(SourceSnapshotBatchResolver); ok {
			out, e = resolver.ResolveSourceSnapshots(bounded, r)
		} else {
			e = targets.ErrUnsupported
		}
	case queryResolveSourceSnapshot:
		var r targets.SourceSnapshotTarget
		if decodeOperationBody(q.Body, &r) != nil || !r.Valid() {
			return contracts.ErrAPIContextProtocol
		}
		if resolver, ok := s.targets.(SourceSnapshotTargetResolver); ok {
			out, e = resolver.ResolveSourceSnapshot(bounded, r)
		} else {
			e = targets.ErrUnsupported
		}
	case queryResolveOngoingRecorders:
		var r []targets.OngoingRecorderRequest
		if decodeOperationBody(q.Body, &r) != nil || !targets.ValidOngoingRecorderBatch(r) {
			return contracts.ErrAPIContextProtocol
		}
		if resolver, ok := s.targets.(OngoingTargetResolver); ok {
			out, e = resolver.ResolveOngoingRecorders(bounded, r)
		} else {
			e = targets.ErrUnsupported
		}
	default:
		return contracts.ErrAPIContextProtocol
	}
	auditapp.MarkStep(call, "r-resolve", resolved)
	reply := contracts.APIContextOperationReply{Format: contracts.APIContextExchangeFormat, Sequence: seq, Method: q.Method}
	if e != nil {
		reply.Failure = queryFailureLabel(e)
	} else if reply.Body, e = json.Marshal(out); e != nil || len(reply.Body) > contracts.APIContextOperationBytes-1024 {
		// An answer that cannot fit one frame is a closed failure, never a
		// truncated answer or a broken exchange (ADR-228).
		reply.Body, reply.Failure = nil, "unavailable"
	}
	encoded, e := contracts.EncodeAPIContextOperationReply(reply)
	if e != nil {
		return e
	}
	defer clear(encoded)
	written := time.Now()
	e = s.writeSourceFrame(bounded, contracts.APIContextFrame{Kind: contracts.APIContextAnswerFrame, Payload: encoded})
	auditapp.MarkStep(call, "r-write", written)
	if e != nil {
		s.record(streamRegionalQueryWrite, streamErrorReason(e))
	}
	return e
}

// queryCheckReason classifies a failed current check; a nil error means the
// returned receiver itself was expired or for another channel.
func queryCheckReason(e error) streamReason {
	if e == nil {
		return streamPeerInvalid
	}
	return streamErrorReason(e)
}
