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
	last    *analysisapp.ContextProjectionDelivery
}

func (p *projectionAuditTarget) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	reply, err := p.adapter.CallWithContext(ctx, current, call, name, raw)
	if reply.owner != nil {
		p.last = reply.owner.guard.(*contextProjectionGuard).delivery
	}
	return reply, err
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

func TestContextProjectionBridgeReadyAndPollOwnTheirReads(t *testing.T) {
	s, f, g, _ := bridgeAuditFixture(t)
	if len(f.i.Scopes) != 1 || f.i.Scopes[0] != "evidence:read" {
		t.Fatal("fixture added raw/download rights")
	}
	first, err := s.Call(context.Background(), f, "get_extract", extractInput("fileExcerpt", bridgeInput()))
	if err != nil {
		t.Fatal(err)
	}
	if first.CheckDisclosure(context.Background()) != nil || f.reads != 1 || f.completions != 0 {
		t.Fatal("read did not retain ownership")
	}
	if s.contracts.ValidateOutput("get_extract", first.Body) != nil {
		t.Fatal("invalid excerpt")
	}
	var initial struct {
		Data struct {
			Lines []string `json:"lines"`
			queryViewTimes
		} `json:"data"`
	}
	if json.Unmarshal(first.Body, &initial) != nil || len(initial.Data.Lines) != 14 {
		t.Fatal("wrong approved output")
	}
	if err = first.Close(context.Background()); err != nil || f.completions != 1 || f.active {
		t.Fatal("read did not join cleanup", err)
	}
	if !bytes.Equal(first.Body, make([]byte, len(first.Body))) {
		t.Fatal("closed owner retained bytes")
	}
	second, err := s.Call(context.Background(), f, "get_query_result", bridgePoll(f.q.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(context.Background())
	if f.starts != 1 || f.polls != 1 || f.reads != 2 || g.events[1].Effect != "accepted" || g.events[1].OperationID == g.events[0].OperationID {
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
	for _, name := range []string{"get_extract", "get_query_result"} {
		raw := extractInput("fileExcerpt", bridgeInput())
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
	if f.admissions != 1 || f.starts != 1 || f.polls != 1 || f.reads != 0 || len(g.events) != 2 || g.events[0].Effect != "accepted" || g.events[1].Effect != "accepted" {
		t.Fatal("pending control effects missing")
	}
}

func TestContextProjectionBridgeRefusesAfterAuditAndJoinsOriginalCleanup(t *testing.T) {
	for _, mode := range []string{"finish", "cancel", "retention", "original lease expiry", "permission", "expired request", "uncertain close"} {
		t.Run(mode, func(t *testing.T) {
			s, f, g, _ := bridgeAuditFixture(t)
			if mode == "original lease expiry" {
				f.a.ValidUntil = f.a.ValidUntil.Add(-time.Second)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g.onRecord = func() {
				switch mode {
				case "finish":
					g.fail = true
				case "cancel":
					cancel()
				case "retention":
					f.a.AccessUntil = f.q.Deadline.Add(-time.Second)
					// The current SQL retention fence is independent of the
					// retained request observation.
					f.permitErr = errors.New("current retention cutoff")
				case "original lease expiry":
					f.now = f.a.ValidUntil
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
			reply, err := s.Call(ctx, f, "get_extract", extractInput("fileExcerpt", bridgeInput()))
			if err == nil || len(reply.Body) != 0 || f.reads != 1 || f.lastRead == nil || !f.lastRead.closed {
				t.Fatal("failed disclosure discarded cleanup", err)
			}
			if !time.Now().Before(f.lastRead.cleanupUntil) {
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
	// The first authority already carries this short original cutoff; later
	// local checks cannot renew it while the HTTP write blocks.
	f.a.ValidUntil = time.Now().Add(500 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reply, err := s.Call(ctx, f, "get_extract", extractInput("fileExcerpt", bridgeInput()))
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close(context.Background())
	d := p.last
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
	// The retained original authority expires while the public socket is
	// blocked. The transport parent itself remains live throughout.
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
	reply, err := s.Call(context.Background(), f, "get_extract", extractInput("fileExcerpt", bridgeInput()))
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
	if reply, err := s.Call(context.Background(), f, "get_extract", extractInput("fileExcerpt", bridgeInput())); err == nil || len(reply.Body) != 0 || f.admissions != 1 || g.events[0].Effect != "unknown" {
		t.Fatal("uncertain admission reported no effect")
	}
}

// extractInput adds the get_extract view to a case/artifact input.
func extractInput(view string, raw []byte) []byte {
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["view"] = view
	b, _ := json.Marshal(m)
	return b
}
