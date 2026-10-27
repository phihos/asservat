package presentation

import (
	"context"
	"strings"
	"testing"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/authorization"
)

func TestAuditedGrantOperationsRefusalAcceptedAndUncertainOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, raw            string
		failure              error
		status, effect, code string
	}{
		{"decide_review", `{"grant_id":"00000000-0000-4000-8000-0000000009a1","decision":"approve","reason":"self must fail","idempotency_key":"self"}`, authorization.ErrSelfApproval, "denied", "none", "SelfApprovalRefused"},
		{"decide_review", `{"grant_id":"00000000-0000-4000-8000-0000000009a1","decision":"approve","reason":"independent","idempotency_key":"approved"}`, nil, "success", "accepted", ""},
		{"revoke_grant", `{"grant_id":"00000000-0000-4000-8000-0000000009a1","expected_revision":2,"idempotency_key":"revoke"}`, nil, "success", "accepted", ""},
		{"decide_review", `{"grant_id":"00000000-0000-4000-8000-0000000009a1","decision":"approve","reason":"uncertain","idempotency_key":"unknown"}`, authapp.ErrGrantUnavailable, "unavailable", "unknown", "NotAvailable"},
	} {
		t.Run(tc.name+"/"+tc.status, func(t *testing.T) {
			s, f, gate := auditedFixture(t)
			uc := &grantUseCase{view: grantView(f.i.VerifiedAt), until: f.metadataUntil, err: tc.failure}
			grants, err := NewGrantOperations(s.inner.PublicOrigin(), s.config.Now, s.config.NewID, uc)
			if err != nil {
				t.Fatal(err)
			}
			s.inner, err = NewInvestigationGrantOperations(s.inner.(*InvestigationOperations), grants)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := s.Call(context.Background(), f, tc.name, []byte(tc.raw))
			if err != nil {
				t.Fatal("audited real GrantOperations returned transport failure", err)
			}
			if tc.code != "" && !strings.Contains(string(reply.Body), `"code":"`+tc.code+`"`) {
				t.Fatal("closed service refusal lost", string(reply.Body))
			}
			if len(gate.intents) != 1 || len(gate.outcomes) != 1 || !gate.outcomes[0].Valid() || gate.outcomes[0].Status != tc.status || gate.outcomes[0].Effect != tc.effect {
				t.Fatal("grant outcome unavailable or misclassified", gate.outcomes)
			}
		})
	}
}

func TestAuditedGrantReplayAndReadEffects(t *testing.T) {
	for _, tc := range []struct {
		name, raw, effect string
		replay            bool
		failure           error
	}{
		{"decide_review", `{"grant_id":"00000000-0000-4000-8000-0000000009a1","decision":"approve","reason":"replay","idempotency_key":"original"}`, "accepted", true, nil},
		{"revoke_grant", `{"grant_id":"00000000-0000-4000-8000-0000000009a1","expected_revision":2,"idempotency_key":"original"}`, "accepted", true, nil},
		{"get_grant", `{"grant_id":"00000000-0000-4000-8000-0000000009a1"}`, "none", false, nil},
		{"list_reviews", `{"view":"pending"}`, "none", false, nil},
		// A current denial cannot establish whether an older same-key attempt
		// committed before the reviewer lost rights. It must not erase uncertainty.
		{"decide_review", `{"grant_id":"00000000-0000-4000-8000-0000000009a1","decision":"approve","reason":"lost reply","idempotency_key":"original"}`, "unknown", false, authorization.ErrNotApprover},
	} {
		t.Run(tc.name+"/"+tc.effect, func(t *testing.T) {
			s, f, gate := auditedFixture(t)
			uc := &grantUseCase{view: grantView(f.i.VerifiedAt), until: f.metadataUntil, replay: tc.replay, err: tc.failure}
			grants, err := NewGrantOperations(s.inner.PublicOrigin(), s.config.Now, s.config.NewID, uc)
			if err != nil {
				t.Fatal(err)
			}
			s.inner, err = NewInvestigationGrantOperations(s.inner.(*InvestigationOperations), grants)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Call(context.Background(), f, tc.name, []byte(tc.raw)); err != nil {
				t.Fatal(err)
			}
			if len(gate.outcomes) != 1 || !gate.outcomes[0].Valid() || gate.outcomes[0].Effect != tc.effect {
				t.Fatal("replay/read/lost-reply effect misclassified", gate.outcomes)
			}
		})
	}
}

func TestAuditedGrantMalformedOutputAndAuditFailureStayBounded(t *testing.T) {
	raw := []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1","decision":"approve","reason":"reviewed","idempotency_key":"original"}`)
	for _, mode := range []string{"invalid grant ID", "intent unavailable", "outcome unavailable"} {
		t.Run(mode, func(t *testing.T) {
			s, f, gate := auditedFixture(t)
			uc := &grantUseCase{view: grantView(f.i.VerifiedAt), until: f.metadataUntil}
			if mode == "invalid grant ID" {
				uc.view.Grant.ID = "not-a-uuid"
			}
			gate.beginFail = mode == "intent unavailable"
			gate.finishFail = mode == "outcome unavailable"
			grants, err := NewGrantOperations(s.inner.PublicOrigin(), s.config.Now, s.config.NewID, uc)
			if err != nil {
				t.Fatal(err)
			}
			s.inner, err = NewInvestigationGrantOperations(s.inner.(*InvestigationOperations), grants)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := s.Call(context.Background(), f, "decide_review", raw)
			if err == nil || len(reply.Body) != 0 {
				t.Fatal("unvalidated/unaudited approval response escaped", err, string(reply.Body))
			}
			if mode == "intent unavailable" {
				if uc.decideCalls != 0 || len(gate.outcomes) != 0 {
					t.Fatal("mutation ran before acknowledged encrypted intent")
				}
				return
			}
			if len(gate.outcomes) != 1 || !gate.outcomes[0].Valid() {
				t.Fatal("bounded outcome not retained", gate.outcomes)
			}
			want := "accepted"
			if mode == "invalid grant ID" {
				want = "unknown"
			}
			if gate.outcomes[0].Effect != want {
				t.Fatal("invalid result or acknowledged effect misclassified", gate.outcomes[0].Effect, want)
			}
		})
	}
}
