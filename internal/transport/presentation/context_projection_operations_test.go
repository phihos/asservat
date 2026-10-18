package presentation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
)

type projectionAuditTarget struct {
	Operations
	adapter *ContextProjectionOperations
	last    *contextQueryInvocation
	mutate  func(*OperationCall, *json.RawMessage)
}

func (p *projectionAuditTarget) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	p.last = call.queryInvocation
	if p.mutate != nil {
		p.mutate(&call, &raw)
	}
	return p.adapter.CallWithContext(ctx, current, call, name, raw)
}

func bridgeAuditFixture(t *testing.T) (*AuditedOperations, *bridgeFixture, *presentationAuditGate, *projectionAuditTarget) {
	t.Helper()
	s, _, g := auditedFixture(t)
	f := newBridgeFixture(t)
	s.config.RootID, s.config.Now, s.config.NewID = bridgeID, func() time.Time { return f.now }, f.next
	a, err := NewContextProjectionOperations(f.s, f.s.Results)
	if err != nil {
		t.Fatal(err)
	}
	p := &projectionAuditTarget{Operations: s.inner, adapter: a}
	s.inner = p
	return s, f, g, p
}
func bridgeInput() []byte {
	b, _ := json.Marshal(map[string]string{"case_id": bridgeID, "artifact_id": bridgeID})
	return b
}
func bridgePoll(id string) []byte {
	b, _ := json.Marshal(map[string]string{"query_handle": id})
	return b
}

func TestContextProjectionBridgeRequiresOriginalAuditInputBeforeEffects(t *testing.T) {
	for _, mode := range []string{"begin", "missing owner", "request ID", "range", "artifact", "wrong branch"} {
		t.Run(mode, func(t *testing.T) {
			s, f, g, p := bridgeAuditFixture(t)
			if mode == "begin" {
				g.beginFail = true
			}
			p.mutate = func(call *OperationCall, raw *json.RawMessage) {
				switch mode {
				case "missing owner":
					call.queryInvocation = nil
				case "request ID":
					call.requestID = f.next()
				case "range":
					*raw = json.RawMessage(`{"case_id":"` + bridgeID + `","artifact_id":"` + bridgeID + `","line_start":2}`)
				case "artifact":
					*raw = json.RawMessage(`{"case_id":"` + bridgeID + `","artifact_id":"00000000-0000-4000-8000-000000000099"}`)
				case "wrong branch":
					if call.queryInvocation.CheckInput(context.Background(), analysisapp.ContextQueryInput{QueryID: bridgeID}) == nil {
						t.Fatal("wrong typed input accepted")
					}
					call.queryInvocation = nil
				}
			}
			out, err := s.Call(context.Background(), f, "get_file_excerpt", bridgeInput())
			if err == nil || len(out.Body) != 0 || f.admissions != 0 || f.starts != 0 || f.reads != 0 {
				t.Fatal("unbound operation dispatched")
			}
			if mode != "begin" && (len(g.outcomes) != 1 || g.outcomes[0].Effect != "none") {
				t.Fatal("pre-dispatch refusal misclassified")
			}
		})
	}
}

func TestContextProjectionBridgeReadyAndPollHaveExactAuditedOwners(t *testing.T) {
	s, f, g, p := bridgeAuditFixture(t)
	if len(f.i.Scopes) != 1 || f.i.Scopes[0] != "evidence:read" {
		t.Fatal("fixture added raw/download rights")
	}
	g.onFinish = func() {
		if p.last.delivery == nil || p.last.CheckOutcome(context.Background(), p.last.delivery) == nil {
			t.Fatal("outcome accepted before Finish acknowledgement")
		}
	}
	first, err := s.Call(context.Background(), f, "get_file_excerpt", bridgeInput())
	if err != nil {
		t.Fatal(err)
	}
	d := p.last.delivery
	if first.CheckDisclosure(context.Background()) != nil || f.reads != 1 || f.completions != 0 || len(s.lanes["normal"]) != 1 {
		t.Fatal("read did not retain ownership")
	}
	if p.last.CheckOutcome(context.Background(), &analysisapp.ContextProjectionDelivery{}) == nil {
		t.Fatal("different pointer accepted")
	}
	if s.contracts.ValidateOutput("get_file_excerpt", first.Body) != nil {
		t.Fatal("invalid excerpt")
	}
	var initial struct {
		Data struct {
			Lines []string `json:"lines"`
			queryViewTimes
		} `json:"data"`
	}
	if json.Unmarshal(first.Body, &initial) != nil || len(initial.Data.Lines) != 14 || !initial.Data.ExpiresAt.Equal(d.QueryDeadline()) {
		t.Fatal("wrong approved output")
	}
	if err = first.Close(context.Background()); err != nil || f.completions != 1 || f.active || len(s.lanes["normal"]) != 0 {
		t.Fatal("read did not join cleanup", err)
	}
	if p.last.CheckOutcome(context.Background(), d) == nil || !bytes.Equal(first.Body, make([]byte, len(first.Body))) {
		t.Fatal("closed owner retained authority or bytes")
	}
	second, err := s.Call(context.Background(), f, "get_query_result", bridgePoll(f.q.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(context.Background())
	if f.starts != 1 || f.polls != 1 || f.reads != 2 || g.outcomes[1].Effect != "accepted" || g.outcomes[1].Intent.ID == g.outcomes[0].Intent.ID {
		t.Fatal("poll restarted worker or reused invocation")
	}
	if s.contracts.ValidateOutput("get_query_result", second.Body) != nil {
		t.Fatal("invalid nested query result")
	}
	var poll struct {
		RequestID string `json:"request_id"`
		Data      struct {
			Result struct {
				RequestID string `json:"request_id"`
			} `json:"result"`
			queryViewTimes
		} `json:"data"`
	}
	if json.Unmarshal(second.Body, &poll) != nil || poll.RequestID != poll.Data.Result.RequestID || !poll.Data.ExpiresAt.Equal(initial.Data.ExpiresAt) {
		t.Fatal("poll changed original query deadline or nested linkage")
	}
}

func TestContextProjectionBridgePendingChargesAndNeverStartsOnPoll(t *testing.T) {
	s, f, g, _ := bridgeAuditFixture(t)
	f.ready = false
	for _, name := range []string{"get_file_excerpt", "get_query_result"} {
		raw := bridgeInput()
		if name == "get_query_result" {
			raw = bridgePoll(f.q.ID)
		}
		reply, err := s.Call(context.Background(), f, name, raw)
		if err != nil {
			t.Fatal(err)
		}
		var result OperationEnvelope
		if json.Unmarshal(reply.Body, &result) != nil || result.Status != "pending" || s.contracts.ValidateOutput(name, reply.Body) != nil {
			t.Fatal("invalid pending")
		}
		if reply.Close(context.Background()) != nil {
			t.Fatal("pending close")
		}
	}
	if f.admissions != 1 || f.starts != 1 || f.polls != 1 || f.reads != 0 || len(g.outcomes) != 2 || g.outcomes[0].Effect != "accepted" || g.outcomes[1].Effect != "accepted" {
		t.Fatal("pending control effects missing")
	}
}

func TestContextProjectionBridgeRefusesAfterAuditAndJoinsOriginalCleanup(t *testing.T) {
	for _, mode := range []string{"finish", "cancel", "retention", "shorter lease", "permission", "expired request", "uncertain close"} {
		t.Run(mode, func(t *testing.T) {
			s, f, g, _ := bridgeAuditFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g.onFinish = func() {
				switch mode {
				case "finish":
					g.finishFail = true
				case "cancel":
					cancel()
				case "retention":
					f.a.AccessUntil = f.q.Deadline.Add(-time.Second)
				case "shorter lease":
					f.a.ValidUntil = f.a.ValidUntil.Add(-time.Second)
				case "permission":
					f.permitErr = errors.New("denied")
				case "expired request":
					f.now = f.i.ValidUntil
				case "uncertain close":
					cancel()
				}
			}
			if mode == "uncertain close" {
				f.closeErr = errors.New("unknown remote closure")
			}
			reply, err := s.Call(ctx, f, "get_file_excerpt", bridgeInput())
			if err == nil || len(reply.Body) != 0 || f.reads != 1 || f.lastRead == nil || !f.lastRead.closed || len(s.lanes["normal"]) != 0 {
				t.Fatal("failed disclosure discarded cleanup", err)
			}
			if !f.lastRead.cleanupUntil.Equal(g.intents[0].WriteUntil) || !time.Now().Before(f.lastRead.cleanupUntil) {
				t.Fatal("cleanup inherited expired public cutoff")
			}
			if mode == "uncertain close" {
				if f.completions != 0 || !f.active {
					t.Fatal("uncertain cleanup fabricated completion")
				}
			} else if f.completions != 1 || f.active {
				t.Fatal("joined cleanup missing")
			}
		})
	}
}

func TestContextProjectionBridgeOwnerExpiryInterruptsBlockedWrite(t *testing.T) {
	s, f, _, p := bridgeAuditFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reply, err := s.Call(ctx, f, "get_file_excerpt", bridgeInput())
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close(context.Background())
	d := p.last.delivery
	writeCtx, finishWrite := reply.ResponseContext(ctx)
	defer finishWrite()
	w := &operationWriter{ResponseRecorder: httptest.NewRecorder(), writeEntered: make(chan struct{}), writeStop: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := WriteOperationResponse(writeCtx, w, http.StatusOK, reply.Body, reply.ValidUntil, reply.CheckDisclosure)
		done <- err
	}()
	select {
	case <-w.writeEntered:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("write did not begin")
	}
	// A separate check by the retained application owner discovers an earlier
	// original authority lease while the public socket is already blocked.
	// The transport request itself remains live throughout this cancellation.
	f.a.ValidUntil = time.Now().Add(50 * time.Millisecond)
	if err = d.CheckDisclosure(context.Background()); err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if err == nil || ctx.Err() != nil || w.Flushed {
			t.Fatal("owner expiry did not independently interrupt write", err)
		}
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("owner cancellation did not reach socket")
	}
	finishWrite()
	if err = reply.Close(context.Background()); err != nil || f.completions != 1 || f.active {
		t.Fatal("write was not joined before exact cleanup", err)
	}
	select {
	case <-reply.owner.lifetimeJoined:
	default:
		t.Fatal("application cancellation watcher not joined")
	}
}

func TestContextProjectionBridgeRechecksBeforeActualWrite(t *testing.T) {
	s, f, _, _ := bridgeAuditFixture(t)
	reply, err := s.Call(context.Background(), f, "get_file_excerpt", bridgeInput())
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close(context.Background())
	f.permitErr = value.ErrUnavailable
	if reply.CheckDisclosure(context.Background()) == nil {
		t.Fatal("authority changed after audit but result stayed available")
	}
}

func TestContextProjectionBridgeErrorsAfterDispatchStayUnknown(t *testing.T) {
	s, f, g, _ := bridgeAuditFixture(t)
	f.queryErr = errors.New("unknown SQL commit")
	if reply, err := s.Call(context.Background(), f, "get_file_excerpt", bridgeInput()); err == nil || len(reply.Body) != 0 || f.admissions != 1 || g.outcomes[0].Effect != "unknown" {
		t.Fatal("uncertain admission reported no effect")
	}
}

func TestContextProjectionBridgePollInputCannotSubstituteAnotherQuery(t *testing.T) {
	s, f, g, p := bridgeAuditFixture(t)
	f.ready = false
	reply, err := s.Call(context.Background(), f, "get_file_excerpt", bridgeInput())
	if err != nil {
		t.Fatal(err)
	}
	if err = reply.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.mutate = func(call *OperationCall, raw *json.RawMessage) {
		original, e := call.queryInvocation.Invocation(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		changed := original
		changed.Until = changed.Until.Add(time.Microsecond)
		if call.queryInvocation.CheckIntent(context.Background(), changed) == nil {
			t.Fatal("original interval changed")
		}
		changed = original
		changed.Principal.ClientID = "different-client"
		if call.queryInvocation.CheckIntent(context.Background(), changed) == nil {
			t.Fatal("client lineage changed")
		}
		*raw = bridgePoll(f.next())
	}
	if out, e := s.Call(context.Background(), f, "get_query_result", bridgePoll(f.q.ID)); e == nil || len(out.Body) != 0 || f.polls != 0 || f.starts != 1 || g.outcomes[1].Effect != "none" {
		t.Fatal("poll input substitution reached effects")
	}
}
