package presentation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type shareOperationsFixture struct {
	scopes    []string
	calls     []string
	input     sharing.CreateInput
	createErr error
}

func (f *shareOperationsFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	now := time.Now()
	return identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "owner", ClientID: "mcp", Kind: identity.Human}, Scopes: f.scopes, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}, nil
}
func (f *shareOperationsFixture) Create(_ context.Context, _ identities.CurrentIdentity, in sharing.CreateInput) (authorization.Share, bool, error) {
	f.calls, f.input = append(f.calls, "create"), in
	return authorization.Share{ID: "11111111-1111-4111-8111-111111111111"}, false, f.createErr
}
func (f *shareOperationsFixture) List(_ context.Context, _ identities.CurrentIdentity, view string, limit int) ([]sharing.View, time.Time, error) {
	f.calls = append(f.calls, "list-"+view)
	issuer := "https://id.example.invalid"
	team := artifact.AudienceAssignment{Kind: "Group", Issuer: issuer, SubjectID: "owners", Role: "evidence-owner", AssignmentID: "33333333-3333-4333-8333-333333333333"}
	again := team
	again.AssignmentID = "44444444-4444-4444-8444-444444444444"
	s := authorization.Share{ID: "11111111-1111-4111-8111-111111111111", CaseID: "22222222-2222-4222-8222-222222222222", ExpiresAt: time.Now().Add(time.Hour), Revision: 1,
		Creator: identity.Principal{Issuer: issuer, Subject: "creator", ClientID: "mcp", Kind: identity.Human}, Management: []artifact.AudienceAssignment{team, again}}
	return []sharing.View{{Share: s, Phase: authorization.ShareSuspended}}, time.Now().Add(5 * time.Second), nil
}
func (f *shareOperationsFixture) Revoke(_ context.Context, _ identities.CurrentIdentity, id string, expected int64, key string) (authorization.Share, bool, error) {
	f.calls = append(f.calls, "revoke")
	return authorization.Share{ID: id, Revision: 2}, false, nil
}

func shareCall(t *testing.T, s *ShareOperations, f *shareOperationsFixture, name, input string) map[string]any {
	t.Helper()
	reply, err := s.CallWithContext(context.Background(), f, OperationCall{requestID: "88888888-8888-4888-8888-888888888888"}, name, json.RawMessage(input))
	if err != nil {
		t.Fatal(name, err)
	}
	var out map[string]any
	if err := json.Unmarshal(reply.Body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestShareOperationsContract(t *testing.T) {
	f := &shareOperationsFixture{scopes: []string{"evidence:read", "evidence:share"}}
	s, err := NewShareOperations("https://asservat.example.invalid", time.Now, func() string { return "88888888-8888-4888-8888-888888888888" }, f)
	if err != nil {
		t.Fatal(err)
	}
	create := `{"case_id":"22222222-2222-4222-8222-222222222222","artifacts":[{"artifactID":"33333333-3333-4333-8333-333333333333","digest":"` + "0a" + `0000000000000000000000000000000000000000000000000000000000000a"}],"recipients":[{"kind":"User","issuer":"https://id.example.invalid","id":"outsider"}],"data_classes":["metadata"],"operations":["get_case"],"expires_at":"2026-10-27T12:00:00Z","reason":"incident review","idempotency_key":"k"}`
	if out := shareCall(t, s, f, "create_share", create); out["status"] != "ok" || out["data"].(map[string]any)["phase"] != "Active" || f.input.Version[0] != 0x0a || f.input.Recipients[0].ID != "outsider" || f.input.ExpiresAt.IsZero() {
		t.Fatal("create reply", out, f.input)
	}
	// The owned view names revision, "Created by" and "Managed by" (one entry
	// per team, not per assignment).
	if out := shareCall(t, s, f, "list_shares", `{"view":"owned"}`); out["status"] != "ok" {
		t.Fatal("list reply", out)
	} else if row := out["data"].(map[string]any)["shares"].([]any)[0].(map[string]any); row["phase"] != "Suspended" || row["revision"] != float64(1) ||
		row["created_by"].(map[string]any)["id"] != "creator" || len(row["managed_by"].([]any)) != 1 || row["managed_by"].([]any)[0].(map[string]any)["id"] != "owners" {
		t.Fatal("owned row", row)
	}
	if out := shareCall(t, s, f, "revoke_share", `{"share_id":"11111111-1111-4111-8111-111111111111","expected_revision":1,"idempotency_key":"r"}`); out["status"] != "ok" || out["data"].(map[string]any)["revision"] != float64(2) {
		t.Fatal("revoke reply", out)
	}
	// Increment 1 rejects every other share shape at the contract.
	for name, input := range map[string]string{
		"create_share": `{"case_id":"22222222-2222-4222-8222-222222222222","artifacts":[{"artifactID":"33333333-3333-4333-8333-333333333333","digest":"` + "0a" + `0000000000000000000000000000000000000000000000000000000000000a"}],"recipients":[{"kind":"User","issuer":"https://id.example.invalid","id":"outsider"}],"data_classes":["metadata","raw"],"operations":["get_case"],"expires_at":"2026-10-27T12:00:00Z","reason":"r","idempotency_key":"k"}`,
		"list_shares":  `{"view":"owned","include_intents":true}`,
		"revoke_share": `{"sharing_intent_id":"11111111-1111-4111-8111-111111111111","expected_revision":1,"idempotency_key":"r"}`,
	} {
		if _, err := s.CallWithContext(context.Background(), f, OperationCall{requestID: "88888888-8888-4888-8888-888888888888"}, name, json.RawMessage(input)); err == nil {
			t.Fatal("unsupported share input accepted", name)
		}
	}
	// Without evidence:share nothing is dispatched; received needs only read.
	f.scopes, f.calls = []string{"evidence:read"}, nil
	for name, input := range map[string]string{"create_share": create, "list_shares": `{"view":"owned"}`, "revoke_share": `{"share_id":"11111111-1111-4111-8111-111111111111","expected_revision":1,"idempotency_key":"r"}`} {
		if out := shareCall(t, s, f, name, input); out["status"] != "error" || out["data"].(map[string]any)["code"] != "NotAvailable" {
			t.Fatal("share operation without evidence:share", name, out)
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("dispatched without evidence:share", f.calls)
	}
	if out := shareCall(t, s, f, "list_shares", `{"view":"received"}`); out["status"] != "ok" || f.calls[0] != "list-received" {
		t.Fatal("received list", out)
	} else if row := out["data"].(map[string]any)["shares"].([]any)[0].(map[string]any); row["created_by"] != nil || row["managed_by"] != nil || row["revision"] != nil {
		t.Fatal("received row exposes management", row)
	}
	f.scopes, f.createErr = []string{"evidence:read", "evidence:share"}, value.ErrCapacity
	if out := shareCall(t, s, f, "create_share", create); out["data"].(map[string]any)["code"] != "ShareLimit" {
		t.Fatal("capacity code", out)
	}
}
