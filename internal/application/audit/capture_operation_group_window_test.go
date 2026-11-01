package audit

import (
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func TestCommittedGroupAuditKeepsOriginalRequestWindow(t *testing.T) {
	executor := authorization.PolicyPrincipal("11111111-1111-4111-8111-111111111111", "policy-uid")
	original, mac, err := captureOperationFixtureFor(t, &executor)
	if err != nil {
		t.Fatal(err)
	}
	c := *original.Capture
	human := identity.Principal{Kind: identity.Human, Issuer: "https://id.example.test", Subject: "user", ClientID: "console"}
	c.Initiator = &human
	c.Group = &value.CaptureGroupBinding{ParentCaptureID: "22222222-2222-4222-8222-222222222222", SelectionDigest: c.ScopeDigest, ChildIndex: 0, ChildCount: 16}
	if !c.Valid() {
		t.Fatal("invalid genuine group control fixture")
	}
	account := captureAdmissionAccount(original, mac)
	for _, span := range []time.Duration{3 * time.Second, 12 * time.Second, 15 * time.Second, 16 * time.Second} {
		t.Run(span.String(), func(t *testing.T) {
			bound := c.CreatedAt.Add(span)
			got, e := PrepareCaptureOperation(c, account, mac, bound)
			want := bound
			if max := c.CreatedAt.Add(15 * time.Second); want.After(max) {
				want = max
			}
			if e != nil || !got.Valid() || !got.RequestUntil.Equal(want) || got.RequestUntil.After(bound) {
				t.Fatalf("original group bookkeeping bound changed: got=%s want=%s err=%v", got.RequestUntil, want, e)
			}
			old := got
			old.RequestUntil = c.CreatedAt.Add(5 * time.Second)
			if !old.Valid() {
				t.Fatal("legacy group five-second record rejected")
			}
			got.RequestUntil = c.CreatedAt.Add(15*time.Second + time.Microsecond)
			if got.Valid() {
				t.Fatal("group exceeded fixed fifteen-second maximum")
			}
		})
	}
	// A longer bookkeeping maximum cannot outlive the accepted processing end.
	short := c
	short.Deadline = c.CreatedAt.Add(8 * time.Second)
	clipped, e := PrepareCaptureOperation(short, account, mac, c.CreatedAt.Add(15*time.Second))
	if e != nil || !clipped.RequestUntil.Equal(short.Deadline) || !clipped.WriteUntil.Equal(short.Deadline) {
		t.Fatal("group audit escaped original processing end", e)
	}
	old, e := PrepareCaptureOperation(c, account, mac, c.CreatedAt.Add(5*time.Second))
	replay, e2 := PrepareCaptureOperation(c, account, mac, old.RequestUntil)
	if e != nil || e2 != nil || !sameOperationRecord(old, replay) {
		t.Fatal("legacy five-second group bytes changed")
	}
	// Missing/malformed group cannot widen ordinary accepted intent dates.
	for _, group := range []*value.CaptureGroupBinding{nil, {ParentCaptureID: c.Group.ParentCaptureID, SelectionDigest: c.ScopeDigest, ChildIndex: 0, ChildCount: 1}} {
		c.Group = group
		got, e := PrepareCaptureOperation(c, account, mac, c.CreatedAt.Add(15*time.Second))
		if group == nil {
			if e != nil || !got.RequestUntil.Equal(c.CreatedAt.Add(5*time.Second)) {
				t.Fatal("singleton audit widened", e)
			}
		} else if e == nil {
			t.Fatal("malformed group acquired audit window")
		}
	}
}
