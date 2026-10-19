package contextstart

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// ADR-179 pre-work target queries. The hub asks on an idle standby; the region
// answers while it still waits for work, so a query never consumes the
// standby. Queries are not operations: no work is verified or executed.
const (
	queryResolveWorkload = "resolve-workload"
	queryResolvePod      = "resolve-pod"
)

// QueryTargets is the region's own cluster target resolver.
type QueryTargets interface {
	ResolveWorkload(context.Context, targets.WorkloadRequest) (targets.PodResolution, error)
	ResolvePod(context.Context, targets.Request) (targets.PodResolution, error)
}

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
// validity, checked after a fresh source pull; the answer is delegated proof
// the caller must not use beyond it. Any error other than errQueryAnswer
// leaves the stream unusable.
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
	if e = s.Send(call, contracts.APIContextFrame{Kind: contracts.APIContextQueryFrame, Payload: payload}); e != nil {
		return time.Time{}, e
	}
	answered := time.Now()
	f, e := s.Receive(call)
	markQuery(ctx, "q-answer", answered)
	if e != nil {
		return time.Time{}, e
	}
	defer clear(f.Payload)
	reply, e := contracts.DecodeAPIContextOperationReply(f.Payload)
	if f.Kind != contracts.APIContextAnswerFrame || e != nil || reply.Sequence != seq || reply.Method != method || (reply.Failure == "") == (len(reply.Body) == 0) {
		s.interruptAt(streamReceiveResult, streamProtocol)
		return time.Time{}, contracts.ErrAPIContextProtocol
	}
	if reply.Failure != "" {
		return time.Time{}, errQueryAnswer{queryFailureError(reply.Failure)}
	}
	if decodeOperationBody(reply.Body, out) != nil {
		s.interruptAt(streamReceiveResult, streamProtocol)
		return time.Time{}, contracts.ErrAPIContextProtocol
	}
	return receiver.ValidUntil, nil
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
	owner, e := s.check(call)
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
	var out targets.PodResolution
	switch q.Method {
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
	default:
		return contracts.ErrAPIContextProtocol
	}
	reply := contracts.APIContextOperationReply{Format: contracts.APIContextExchangeFormat, Sequence: seq, Method: q.Method}
	if e != nil {
		reply.Failure = queryFailureLabel(e)
	} else if reply.Body, e = json.Marshal(out); e != nil {
		reply.Body, reply.Failure = nil, "unavailable"
	}
	encoded, e := contracts.EncodeAPIContextOperationReply(reply)
	if e != nil {
		return e
	}
	defer clear(encoded)
	if e = s.writeSourceFrame(bounded, contracts.APIContextFrame{Kind: contracts.APIContextAnswerFrame, Payload: encoded}); e != nil {
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
