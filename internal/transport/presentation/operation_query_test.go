package presentation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/audit"
)

const queryInput = `{"case_id":"00000000-0000-4000-8000-000000000001","artifact_id":"00000000-0000-4000-8000-000000000002"}`

type replyGuardFixture struct {
	check          func(context.Context) error
	close          func(context.Context) error
	checks, closes atomic.Int32
}

func (g *replyGuardFixture) CheckDisclosure(ctx context.Context) error {
	g.checks.Add(1)
	if g.check != nil {
		return g.check(ctx)
	}
	return ctx.Err()
}
func (g *replyGuardFixture) Close(ctx context.Context) error {
	g.closes.Add(1)
	if g.close != nil {
		return g.close(ctx)
	}
	return ctx.Err()
}

type queryAuditTarget struct {
	Operations
	guard        *replyGuardFixture
	ctx          context.Context
	body         []byte
	acknowledged bool
	ackErr       bool
	noGuard      bool
	invalidBody  bool
	effect       operationAuditEffect
}

func (q *queryAuditTarget) CallWithContext(ctx context.Context, _ identities.CurrentIdentity, call OperationCall, name string, _ json.RawMessage) (OperationReply, error) {
	q.ctx = ctx
	now := time.Now().UTC().Truncate(time.Microsecond)
	until, _ := ctx.Deadline()
	x := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "pending", Data: map[string]any{"query_handle": "test-query", "retry_after_seconds": 1, "query_observed_at": now, "query_expires_at": now.Add(10 * time.Second)}, Warnings: []string{}, Provenance: []any{}}
	// Use the canonical shape directly, independent of a public registration.
	b, err := json.Marshal(x)
	if err != nil {
		return OperationReply{}, err
	}
	if q.invalidBody {
		b = []byte(`{"not":"canonical"}`)
	}
	q.body = b
	reply := OperationReply{Body: b, ValidUntil: until, auditEffect: q.effect}
	if q.noGuard {
		return reply, nil
	}
	return ownOperationReply(ctx, reply, q.guard, now.Add(30*time.Second), func(_ context.Context, out audit.OperationOutcome) error {
		if q.ackErr {
			return errors.New("ack association mismatch")
		}
		if out.Intent.ID != call.requestID || out.OutputBytes != int64(len(b)) {
			return errors.New("wrong association")
		}
		q.acknowledged = true
		return nil
	})
}

func queryAuditFixture(t *testing.T) (*AuditedOperations, *contextOperationFixture, *presentationAuditGate, *queryAuditTarget) {
	s, f, g := auditedFixture(t)
	q := &queryAuditTarget{Operations: s.inner, guard: &replyGuardFixture{}, effect: operationEffectAccepted}
	s.inner = q
	return s, f, g, q
}

func TestContextQueryAuditNormalization(t *testing.T) {
	s, _, _, _ := queryAuditFixture(t)
	a, e := s.normalize("get_file_excerpt", []byte(queryInput))
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	_ = json.Unmarshal([]byte(queryInput), &v)
	v["line_start"], v["max_lines"] = 1, 200
	b, _ := json.Marshal(v)
	b, e = s.normalize("get_file_excerpt", b)
	if e != nil || !bytes.Equal(a, b) {
		t.Fatal("omission changed defaults", e)
	}
	v["line_start"] = 2
	b, _ = json.Marshal(v)
	b, e = s.normalize("get_file_excerpt", b)
	if e != nil || bytes.Equal(a, b) {
		t.Fatal("line range omitted from audit input")
	}
	p, e := s.normalize("get_query_result", []byte(`{"query_handle":"first"}`))
	if e != nil {
		t.Fatal(e)
	}
	r, e := s.normalize("get_query_result", []byte(`{"query_handle":"second"}`))
	if e != nil || bytes.Equal(p, r) {
		t.Fatal("query handle omitted")
	}
	if !bytes.Contains(a, []byte("approved-pod-status-display/v1")) {
		t.Fatal("display version omitted")
	}
}

func TestContextQueryAuditPendingEffectsAndOwnedReply(t *testing.T) {
	for _, effect := range []operationAuditEffect{operationEffectNone, operationEffectAccepted, operationEffectUnknown} {
		s, f, g, q := queryAuditFixture(t)
		q.effect = effect
		reply, err := s.Call(context.Background(), f, "get_file_excerpt", []byte(queryInput))
		if err != nil {
			t.Fatalf("%+v intents=%d outcomes=%d dispatched=%v", err, len(g.intents), len(g.outcomes), q.ctx != nil)
		}
		want := map[operationAuditEffect]string{operationEffectNone: "none", operationEffectAccepted: "accepted", operationEffectUnknown: "unknown"}[effect]
		if len(g.outcomes) != 1 || g.outcomes[0].Status != "success" || g.outcomes[0].Effect != want || g.intents[0].InputFormat != "context-query-input/v1" || !q.acknowledged {
			t.Fatal("pending effect/audit mismatch", g.outcomes)
		}
		if q.ctx.Err() != nil || len(s.lanes["normal"]) != 1 || reply.CheckDisclosure(context.Background()) != nil {
			t.Fatal("reply owner ended before transport")
		}
		copy := reply
		if err := copy.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if reply.Close(context.Background()) != nil || q.guard.closes.Load() != 1 || q.ctx.Err() == nil || len(s.lanes["normal"]) != 0 || !bytes.Equal(q.body, make([]byte, len(q.body))) {
			t.Fatal("copy lost joined owner")
		}
		if reply.CheckDisclosure(context.Background()) == nil {
			t.Fatal("closed reply disclosed")
		}
	}
}

func TestContextQueryAuditFailureClosesBeforeDiscard(t *testing.T) {
	for _, mode := range []string{"finish", "invalid", "ack", "guard", "cancel", "missing guard", "missing effect"} {
		t.Run(mode, func(t *testing.T) {
			s, f, g, q := queryAuditFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "finish":
				g.finishFail = true
			case "invalid":
				q.invalidBody = true
			case "ack":
				q.ackErr = true
			case "guard":
				q.guard.check = func(context.Context) error { return errors.New("deny after audit") }
			case "cancel":
				g.onFinish = cancel
			case "missing guard":
				q.noGuard = true
			case "missing effect":
				q.effect = operationEffectUnspecified
			}
			if reply, err := s.Call(ctx, f, "get_file_excerpt", []byte(queryInput)); err == nil || len(reply.Body) != 0 {
				t.Fatal("failed result escaped")
			}
			if !q.noGuard && q.guard.closes.Load() != 1 {
				t.Fatal("owner discarded without cleanup")
			}
			if len(s.lanes["normal"]) != 0 {
				t.Fatal("slot leaked")
			}
		})
	}
}

func TestContextQuerySchemasDoNotRegisterTools(t *testing.T) {
	s, _, _, q := queryAuditFixture(t)
	for _, name := range []string{"get_file_excerpt", "get_query_result"} {
		if _, ok := s.contracts.Tool(name); !ok {
			t.Fatal("schema absent")
		}
		if _, ok := q.Tool(name); ok || BrowserOperationSupported(q, name) {
			t.Fatal("schema enabled route")
		}
	}
}
