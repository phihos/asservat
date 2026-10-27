package presentation

import (
	"context"
	"strings"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-239 fixtures: an activation that shares, and a share service that
// also revokes a policy acceptance's recurring sharing.
type sharingActivationFixture struct {
	policyOperationsFixture
	result app.PolicyActivationResult
	err    error
}

func (f *sharingActivationFixture) Activate(context.Context, identities.CurrentIdentity, string, string, bool) (app.PolicyActivationResult, error) {
	return f.result, f.err
}

type policyRevokeFixture struct {
	shareOperationsFixture
	acceptance string
	expected   int64
	stopped    bool
}

func (f *policyRevokeFixture) StopPolicySharing(_ context.Context, _ identities.CurrentIdentity, acceptance string, expected int64, _ string) (sharing.PolicyRevokeResult, error) {
	f.acceptance, f.expected, f.stopped = acceptance, expected, true
	return sharing.PolicyRevokeResult{AcceptanceID: acceptance}, nil
}

func (f *policyRevokeFixture) RevokePolicySharing(_ context.Context, _ identities.CurrentIdentity, acceptance string, expected int64, _ string) (sharing.PolicyRevokeResult, error) {
	f.acceptance, f.expected = acceptance, expected
	return sharing.PolicyRevokeResult{AcceptanceID: acceptance, Revoked: 3}, nil
}

func policyShareInstruction(end time.Time) *value.PolicyShareInstruction {
	creator := identity.Principal{Issuer: "https://id.example.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}
	return &value.PolicyShareInstruction{Creator: creator, Management: []artifact.AudienceAssignment{{Kind: "Group", Issuer: creator.Issuer, SubjectID: "team-a", Role: "evidence-owner", BasisKind: "AccessBinding", BasisUID: "b", AssignmentID: "55555555-5555-4555-8555-555555555555"}},
		Recipients: []authorization.ShareRecipient{{Kind: "Group", Issuer: creator.Issuer, ID: "incident"}, {Kind: "User", Issuer: creator.Issuer, ID: "oncall"}}, MaxCaptures: 10, NotAfter: end}
}

func TestPolicyActivationStatesThatRepeatedCollectionsWillBeShared(t *testing.T) {
	end := time.Date(2026, 10, 28, 18, 0, 0, 0, time.UTC)
	f := &sharingActivationFixture{policyOperationsFixture: policyOperationsFixture{scopes: []string{"evidence:read", "evidence:capture"}},
		result: app.PolicyActivationResult{PolicyUID: "policy-uid", AcceptanceID: "99999999-9999-4999-8999-999999999999", NotAfter: time.Now().Add(time.Hour), MaxExecutions: 10, Audited: true, Sharing: policyShareInstruction(end)}}
	s, err := NewPolicyOperations("https://asservat.example.invalid", time.Now, func() string { return "88888888-8888-4888-8888-888888888888" }, f, f, f)
	if err != nil {
		t.Fatal(err)
	}
	out := policyCall(t, s, &f.policyOperationsFixture, "activate_policy", `{"policy_name":"restarts","idempotency_key":"k"}`)
	data, _ := out["data"].(map[string]any)
	sharingData, _ := data["sharing"].(map[string]any)
	warnings, _ := out["warnings"].([]any)
	if out["status"] != "ok" || sharingData["statement"] != "Repeated collections will be shared" || sharingData["recipients"] != float64(2) || sharingData["max_captures"] != float64(10) || sharingData["not_after"] != "2026-10-28T18:00:00Z" {
		t.Fatal("activation sharing", out)
	}
	if len(warnings) != 1 || !strings.HasPrefix(warnings[0].(string), "Repeated collections will be shared with 2 recipient(s)") {
		t.Fatal("activation warning", warnings)
	}
	// Without sharing_reviewed the server returns the review: the statement,
	// the recipients, the capture limit and the end.
	f.result, f.err = app.PolicyActivationResult{}, app.PolicySharingReview{Instruction: *policyShareInstruction(end)}
	out = policyCall(t, s, &f.policyOperationsFixture, "activate_policy", `{"policy_name":"restarts","idempotency_key":"k"}`)
	review, _ := out["data"].(map[string]any)
	if out["status"] != "error" || review["code"] != "SharingReviewRequired" || !strings.HasPrefix(review["message"].(string), "Repeated collections will be shared with Group incident, User oncall: at most the next 10 capture(s) of this policy until 2026-10-28T18:00:00Z") {
		t.Fatal("sharing review", out)
	}
	if out = policyCall(t, s, &f.policyOperationsFixture, "activate_policy", `{"policy_name":"restarts","idempotency_key":"k","sharing_reviewed":true}`); out["status"] != "error" {
		t.Fatal("reviewed activation input refused", out)
	}
	f.result, f.err = app.PolicyActivationResult{}, value.ErrSharingDenied
	if out = policyCall(t, s, &f.policyOperationsFixture, "activate_policy", `{"policy_name":"restarts","idempotency_key":"k"}`); out["status"] != "error" || out["data"].(map[string]any)["code"] != "SharingNotPermitted" {
		t.Fatal("sharing refusal", out)
	}
	// Status reports the derived sharing state and the counter.
	f.status = value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: "99999999-9999-4999-8999-999999999999", Generation: 2, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, MaxExecutions: 10, NotAfter: time.Now().Add(time.Hour),
		Sharing: &value.PolicySharingStatus{Instruction: *policyShareInstruction(time.Now().Add(time.Hour)), Spent: 4}}
	out = policyCall(t, s, &f.policyOperationsFixture, "get_policy_status", `{"policy_name":"restarts"}`)
	status, _ := out["data"].(map[string]any)["sharing"].(map[string]any)
	if out["status"] != "ok" || status["state"] != "policyChanged" || status["revision"] != float64(1) || status["shared_captures"] != float64(4) || status["max_captures"] != float64(10) || status["recipients"] != float64(2) {
		t.Fatal("status sharing", out)
	}
	f.status.Sharing.StoppedAt = time.Now()
	out = policyCall(t, s, &f.policyOperationsFixture, "get_policy_status", `{"policy_name":"restarts"}`)
	if status, _ = out["data"].(map[string]any)["sharing"].(map[string]any); status["state"] != "stopped" || status["revision"] != float64(2) || status["stopped_at"] == nil {
		t.Fatal("stopped sharing status", out)
	}
}

func TestRevokeShareBySharingIntentRevokesTheAcceptance(t *testing.T) {
	f := &policyRevokeFixture{shareOperationsFixture: shareOperationsFixture{scopes: []string{"evidence:read", "evidence:share"}}}
	s, err := NewShareOperations("https://asservat.example.invalid", time.Now, func() string { return "88888888-8888-4888-8888-888888888888" }, f)
	if err != nil {
		t.Fatal(err)
	}
	out := shareCall(t, s, &f.shareOperationsFixture, "revoke_share", `{"sharing_intent_id":"99999999-9999-4999-8999-999999999999","expected_revision":1,"idempotency_key":"r"}`)
	data, _ := out["data"].(map[string]any)
	if out["status"] != "ok" || data["sharing_intent_id"] != "99999999-9999-4999-8999-999999999999" || data["revision"] != float64(2) || data["phase"] != "Revoked" || data["share_id"] != nil || f.acceptance != "99999999-9999-4999-8999-999999999999" || f.expected != 1 || len(f.calls) != 0 {
		t.Fatal("revoke-all reply", out, f.calls)
	}
	out = shareCall(t, s, &f.shareOperationsFixture, "stop_future_sharing", `{"sharing_intent_id":"99999999-9999-4999-8999-999999999999","expected_revision":1,"idempotency_key":"s"}`)
	if data, _ := out["data"].(map[string]any); out["status"] != "ok" || data["state"] != "Stopped" || data["revision"] != float64(2) || !f.stopped {
		t.Fatal("stop reply", out)
	}
	// Exactly one target: both or neither is invalid input.
	if _, err := s.CallWithContext(context.Background(), &f.shareOperationsFixture, OperationCall{requestID: "88888888-8888-4888-8888-888888888888"}, "revoke_share", []byte(`{"share_id":"11111111-1111-4111-8111-111111111111","sharing_intent_id":"99999999-9999-4999-8999-999999999999","expected_revision":1,"idempotency_key":"r"}`)); err == nil {
		t.Fatal("both targets accepted")
	}
}
