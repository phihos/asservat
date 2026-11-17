package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
)

// ADR-335 D5: request_capture hands its own input to the approval gate, and
// approval submits that stored input through the same request path.
func TestApprovedSubmissionReplaysRequestCaptureInput(t *testing.T) {
	s, f := operationFixture(t, true)
	if reply, err := s.Call(t.Context(), f, "request_capture", []byte(wireRequest)); err != nil || f.requests != 1 || len(f.submission) == 0 {
		t.Fatalf("request: %v %s", err, reply.Body)
	}
	stored, key, plan := f.submission, f.key, f.plan
	id, err := s.SubmitApproved(t.Context(), f, stored)
	if err != nil || id != "00000000-0000-4000-8000-000000000030" || f.requests != 2 || f.key != key || f.plan != plan {
		t.Fatal("approved submission differs from the request", id, err, f.key)
	}
	f.i.Scopes = []string{"evidence:read"}
	if _, err = s.SubmitApproved(t.Context(), f, stored); !errors.Is(err, value.ErrDenied) || f.requests != 2 {
		t.Fatal("submission without evidence:capture", err)
	}
}

// Approval submits the stored request as the requester with the recorded
// groups only before the recorded end of the requester's authentication.
func TestDecideReviewSubmitsStoredRequest(t *testing.T) {
	base, f := operationFixture(t, true)
	now := f.i.VerifiedAt
	uc := &grantUseCase{view: grantView(now), until: f.metadataUntil}
	g := &uc.view.Grant
	g.Submission = &authorization.GrantSubmission{Request: []byte(`{"idempotency_key":"k"}`), Groups: []string{"payments-devs"}, Scopes: []string{"evidence:read", "evidence:capture"}, Policy: f.i.Policy, Until: now.Add(time.Hour)}
	s, err := NewGrantOperations("https://console.invalid", base.config.Now, func() string { return "00000000-0000-4000-8000-000000000099" }, uc)
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	s.Submit = func(ctx context.Context, current identities.CurrentIdentity, raw []byte) (string, error) {
		calls++
		i, err := current.ResolveIdentity(ctx)
		if err != nil || i.Principal != g.Requester || !slices.Equal(i.Groups, g.Submission.Groups) || i.ValidUntil.After(g.Submission.Until) || string(raw) != string(g.Submission.Request) {
			t.Fatal("submitted as another identity", i, err, string(raw))
		}
		return g.CaptureID, nil
	}
	decide := func(decision string) []string {
		t.Helper()
		reply, err := s.Call(t.Context(), f, "decide_review", []byte(`{"grant_id":"`+g.ID+`","decision":"`+decision+`","reason":"incident 42","idempotency_key":"d1"}`))
		var out struct {
			Status   string   `json:"status"`
			Warnings []string `json:"warnings"`
		}
		if err != nil || json.Unmarshal(reply.Body, &out) != nil || out.Status != "ok" {
			t.Fatalf("decide_review: %v %s", err, reply.Body)
		}
		return out.Warnings
	}
	if w := decide("approve"); calls != 1 || len(w) != 0 {
		t.Fatal("approval did not submit", calls, w)
	}
	if w := decide("deny"); calls != 1 || len(w) != 0 {
		t.Fatal("denial submitted", calls, w)
	}
	// The fake decides at now: an authentication that ended by then is not used.
	g.Submission.Until = now
	if w := decide("approve"); calls != 1 || !slices.Equal(w, []string{"RequesterReauthenticationRequired"}) {
		t.Fatal("expired requester authentication used", calls, w)
	}
	g.Submission.Until = now.Add(time.Hour)
	s.Submit = func(context.Context, identities.CurrentIdentity, []byte) (string, error) { return "", value.ErrChanged }
	if w := decide("approve"); len(w) != 1 || w[0] != publicCaptureFailure(value.ErrChanged, true).Code {
		t.Fatal("submission failure not reported", w)
	}
}
