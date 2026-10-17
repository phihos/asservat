package presentation

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestIngressRejectionHasNoDispatchAndPreservesFinalDeadline(t *testing.T) {
	for _, kind := range []IngressRejectionKind{IngressInvalid, IngressDenied} {
		s, f, g := auditedFixture(t)
		until, err := s.RejectBeforeDispatch(context.Background(), f, IngressRejection{"resolve_capture_request", []byte("sensitive-user-data"), kind})
		if err != nil || until.IsZero() || until.After(f.i.ValidUntil) || f.requests != 0 || f.resolutions != 0 || len(g.intents) != 1 || g.intents[0].Name != "invalid_operation" || len(g.outcomes) != 1 || g.outcomes[0].Effect != "none" {
			t.Fatal("rejection dispatched or lacks bounded audit", err)
		}
		raw, _ := json.Marshal(g.intents)
		if bytes.Contains(raw, []byte("sensitive-user-data")) || bytes.Contains(raw, []byte("resolve_capture_request")) {
			t.Fatal("rejected input persisted as plaintext")
		}
	}
	for _, mode := range []string{"expiry", "cancel", "acknowledgement"} {
		t.Run(mode, func(t *testing.T) {
			s, f, g := auditedFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g.onFinish = func() {
				switch mode {
				case "expiry":
					s.config.Now = func() time.Time { return f.i.ValidUntil }
				case "cancel":
					cancel()
				case "acknowledgement":
					g.finishFail = true
				}
			}
			until, err := s.RejectBeforeDispatch(ctx, f, IngressRejection{RequestedOperation: "resolve_capture_request", Input: []byte("{}"), Kind: IngressInvalid})
			if err == nil || !until.IsZero() || len(g.outcomes) != 1 || f.resolutions != 0 {
				t.Fatal("late rejection disclosed or dispatched")
			}
		})
	}
}
func TestIngressNamesAreBoundedAndBinaryExactUnderMAC(t *testing.T) {
	s, f, g := auditedFixture(t)
	for _, name := range []string{strings.Repeat("x", 8192), "bad\xff", "bad\xfe"} {
		if _, e := s.RejectBeforeDispatch(context.Background(), f, IngressRejection{name, []byte("{}"), IngressInvalid}); e != nil {
			t.Fatal(e)
		}
	}
	if g.intents[1].InputDigest == g.intents[2].InputDigest {
		t.Fatal("invalid UTF-8 names collapsed")
	}
	if _, e := s.RejectBeforeDispatch(context.Background(), f, IngressRejection{strings.Repeat("x", 8193), nil, IngressInvalid}); e == nil || len(g.intents) != 3 {
		t.Fatal("unbounded name admitted")
	}
	if _, e := s.RejectBeforeDispatch(context.Background(), f, IngressRejection{"get_case", nil, 99}); e == nil {
		t.Fatal("open rejection category")
	}
}
func TestIngressCountersSaturateWithoutDynamicLabels(t *testing.T) {
	var c IngressCounters
	c.values[IngressOverloaded].Store(^uint64(0) - 1)
	c.Add(IngressOverloaded)
	c.Add(IngressOverloaded)
	c.Add(255)
	if got := c.Snapshot(); got.Overloaded != ^uint64(0) || got.PreAdmission != 0 {
		t.Fatal(got)
	}
}
