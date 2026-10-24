package presentation

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

// Exercise the real operation routing snapshot and audit wrapper around C18.
// Underlying SQL/native authority remains the explicit bridge component fixture.
func composedProjectionFixture(t *testing.T) (*AuditedOperations, *bridgeFixture, *presentationAuditGate, *InvestigationOperations) {
	t.Helper()
	s, _, g := auditedFixture(t)
	base := s.inner.(*InvestigationOperations)
	f := newBridgeFixture(t)
	s.config.RootID, s.config.Now, s.config.NewID = bridgeID, func() time.Time { return f.now }, f.next
	projection, err := NewContextProjectionOperations(f.s, f.s.Results)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := NewInvestigationProjectionOperations(base, projection)
	if err != nil {
		t.Fatal(err)
	}
	s.inner = combined
	return s, f, g, base
}

func TestInvestigationProjectionIsExplicitAuditedComposition(t *testing.T) {
	s, f, _, base := composedProjectionFixture(t)
	want := append(base.ToolNames(), "get_file_excerpt", "get_query_result")
	slices.Sort(want)
	if !slices.Equal(s.ToolNames(), want) || s.PublicOrigin() != base.PublicOrigin() {
		t.Fatal("changed unrelated operation set or origin")
	}
	names := s.ToolNames()
	names[0] = "forged"
	if !slices.Equal(s.ToolNames(), want) {
		t.Fatal("mutable advertised inventory")
	}
	for _, name := range []string{"get_file_excerpt", "get_query_result"} {
		if _, ok := base.Tool(name); ok || BrowserOperationSupported(base, name) {
			t.Fatal("unconfigured query advertised", name)
		}
		tool, ok := s.Tool(name)
		if !ok || tool.Name != name || !BrowserOperationSupported(s, name) {
			t.Fatal("composed query missing", name)
		}
		input := bridgeInput()
		if name == "get_query_result" {
			input = bridgePoll(bridgeID)
		}
		out, err := s.inner.Call(context.Background(), f, name, input)
		if err == nil || len(out.Body) != 0 {
			t.Fatal("unaudited Call dispatched", name)
		}
		out, err = s.inner.CallWithContext(context.Background(), f, OperationCall{requestID: bridgeID}, name, input)
		if err == nil || len(out.Body) != 0 {
			t.Fatal("server ID alone dispatched", name)
		}
	}
	if f.admissions != 0 || f.starts != 0 || f.reads != 0 {
		t.Fatal("unaudited effects")
	}
	combined := s.inner.(*InvestigationOperations)
	if _, err := NewInvestigationProjectionOperations(combined, combined.projection); err == nil {
		t.Fatal("duplicate registration")
	}
	for _, projection := range []*ContextProjectionOperations{nil, {}, {excerpts: f.s}, {results: f.s.Results}} {
		if _, err := NewInvestigationProjectionOperations(base, projection); err == nil {
			t.Fatal("incomplete registration")
		}
	}
}

type projectionRequestMarker struct{}
type projectionCurrent struct {
	t        *testing.T
	f        *bridgeFixture
	original context.Context
	calls    int
}

func (c *projectionCurrent) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	c.calls++
	until, _ := c.original.Deadline()
	got, ok := ctx.Deadline()
	if !ok || got.After(until) || ctx.Value(projectionRequestMarker{}) != "original" {
		c.t.Fatal("lost original current request")
	}
	return c.f.ResolveIdentity(ctx)
}

func TestInvestigationProjectionUsesReadScopeAndOriginalLiveOwner(t *testing.T) {
	s, f, g, _ := composedProjectionFixture(t)
	if !slices.Equal(f.i.Scopes, []string{"evidence:read"}) {
		t.Fatal("fixture grants download")
	}
	ctx, cancel := context.WithDeadline(context.WithValue(t.Context(), projectionRequestMarker{}, "original"), f.now.Add(3*time.Second))
	defer cancel()
	current := &projectionCurrent{t: t, f: f, original: ctx}
	for _, name := range []string{"get_file_excerpt", "get_query_result"} {
		input := bridgeInput()
		if name == "get_query_result" {
			input = bridgePoll(f.q.ID)
		}
		reply, err := s.Call(ctx, current, name, input)
		if err != nil {
			t.Fatal(name, err)
		}
		if current.calls < 2 || reply.CheckDisclosure(ctx) != nil || len(s.lanes["normal"]) != 1 {
			t.Fatal("lost live identity, disclosure or audit ownership")
		}
		if s.contracts.ValidateOutput(name, reply.Body) != nil {
			t.Fatal("invalid canonical output")
		}
		var envelope struct {
			RequestID string `json:"request_id"`
		}
		if json.Unmarshal(reply.Body, &envelope) != nil || envelope.RequestID != g.intents[len(g.intents)-1].ID {
			t.Fatal("wrong invocation")
		}
		if err = reply.Close(context.Background()); err != nil || len(s.lanes["normal"]) != 0 {
			t.Fatal("unjoined reply", err)
		}
	}
	if f.admissions != 1 || f.starts != 1 || f.polls != 1 || f.reads != 2 || f.completions != 2 || len(g.intents) != 2 || len(g.outcomes) != 2 {
		t.Fatal("poll replaced original query or skipped audit")
	}
	if g.intents[0].ID == g.intents[1].ID || g.outcomes[0].Effect != "accepted" || g.outcomes[1].Effect != "accepted" {
		t.Fatal("reused invocation or effect-free query")
	}
}

func TestInvestigationProjectionRefusesLostCurrentIdentityAroundAudit(t *testing.T) {
	for _, mode := range []string{"no read scope", "begin failure", "changed after begin", "canceled after begin", "changed after finish", "finish failure"} {
		t.Run(mode, func(t *testing.T) {
			s, f, g, _ := composedProjectionFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			wantReads := 0
			switch mode {
			case "no read scope":
				f.i.Scopes = []string{"evidence:download"}
			case "begin failure":
				g.beginFail = true
			case "changed after begin":
				g.onBegin = func() { f.i.Principal.ClientID = "changed-client" }
			case "canceled after begin":
				g.onBegin = cancel
			case "changed after finish":
				wantReads = 1
				g.onFinish = func() { f.i.Policy.Generation++ }
			case "finish failure":
				wantReads = 1
				g.finishFail = true
			}
			reply, err := s.Call(ctx, f, "get_file_excerpt", bridgeInput())
			if err == nil || len(reply.Body) != 0 || f.reads != wantReads || f.active || len(s.lanes["normal"]) != 0 {
				t.Fatal("lost authority disclosed or leaked owner", err, f.reads, f.active)
			}
			if wantReads == 0 && (f.admissions != 0 || f.starts != 0) {
				t.Fatal("pre-audit failure had effects")
			}
		})
	}
}
