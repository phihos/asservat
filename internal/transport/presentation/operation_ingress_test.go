package presentation

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestIngressRejectionHasNoDispatchAndPreservesFinalDeadline(t *testing.T) {
	for _, kind := range []IngressRejectionKind{IngressInvalid, IngressDenied} {
		s, f, g := auditedFixture(t)
		until, err := s.RejectBeforeDispatch(context.Background(), f, IngressRejection{"request_capture", []byte("sensitive-user-data"), kind})
		if err != nil || until.IsZero() || until.After(f.i.ValidUntil) || f.requests != 0 || len(g.events) != 1 || g.events[0].Operation != "invalid_operation" || g.events[0].Effect != "none" {
			t.Fatal("rejection dispatched or lacks bounded audit", err)
		}
		raw, _ := json.Marshal(g.events)
		if bytes.Contains(raw, []byte("sensitive-user-data")) || bytes.Contains(raw, []byte("request_capture")) {
			t.Fatal("rejected input persisted as plaintext")
		}
	}
	s, f, g := auditedFixture(t)
	g.fail = true
	until, err := s.RejectBeforeDispatch(context.Background(), f, IngressRejection{RequestedOperation: "request_capture", Input: []byte("{}"), Kind: IngressInvalid})
	if err == nil || !until.IsZero() || len(g.events) != 1 {
		t.Fatal("unaudited rejection disclosed or dispatched")
	}
}
func TestIngressNamesAreBoundedAndBinaryExactUnderMAC(t *testing.T) {
	s, f, g := auditedFixture(t)
	for _, name := range []string{strings.Repeat("x", 8192), "bad\xff", "bad\xfe"} {
		if _, e := s.RejectBeforeDispatch(context.Background(), f, IngressRejection{name, []byte("{}"), IngressInvalid}); e != nil {
			t.Fatal(e)
		}
	}
	if *g.events[1].InputDigest == *g.events[2].InputDigest {
		t.Fatal("invalid UTF-8 names collapsed")
	}
	if _, e := s.RejectBeforeDispatch(context.Background(), f, IngressRejection{strings.Repeat("x", 8193), nil, IngressInvalid}); e == nil || len(g.events) != 3 {
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
