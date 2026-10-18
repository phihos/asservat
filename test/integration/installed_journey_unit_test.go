package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// These tokens are deliberately unsigned synthetic scheduling inputs. Only the
// native journey exercises signature verification at the actual public server.
func installedSchedulingToken(t *testing.T, now time.Time, subject, resource string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"iss": "https://id.example.invalid/realms/test", "sub": subject, "azp": "mcp", "aud": resource, "exp": now.Add(5 * time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
}

func TestInstalledJourneyRefreshesOriginalIdentityBeforeTokenExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	resource := "https://app.example.invalid/mcp"
	logins, refreshes := 0, 0
	source := &installedJourneyTokenSource{issuer: "https://id.example.invalid/realms/test", resource: resource, now: func() time.Time { return now }}
	source.login = func() kcTokens {
		logins++
		return kcTokens{Access: installedSchedulingToken(t, now, "developer", resource), Refresh: "first-refresh"}
	}
	source.refresh = func(token string) kcTokens {
		refreshes++
		want := "first-refresh"
		if refreshes == 2 {
			want = "second-refresh"
		}
		if token != want {
			t.Fatal("refresh did not retain the rotating original credential", token)
		}
		return kcTokens{Access: installedSchedulingToken(t, now, "developer", resource), Refresh: "second-refresh"}
	}
	first, err := source.Token(t.Context())
	if err != nil || first == "" {
		t.Fatal("first login", err)
	}
	now = now.Add(4 * time.Minute)
	same, err := source.Token(t.Context())
	if err != nil || same != first || logins != 1 || refreshes != 0 {
		t.Fatal("unnecessary login/refresh", err)
	}
	now = now.Add(31 * time.Second)
	next, err := source.Token(t.Context())
	if err != nil || next == first || logins != 1 || refreshes != 1 {
		t.Fatal("token was not refreshed before expiry", err)
	}
	now = now.Add(5 * time.Minute)
	if _, err := source.Token(t.Context()); err != nil || refreshes != 2 {
		t.Fatal("second rotation", err)
	}
}

func TestInstalledJourneyRefusesChangedRefreshIdentityAndCancelledRequests(t *testing.T) {
	for _, change := range []string{"subject", "audience", "issuer", "expired", "malformed", "missing-refresh"} {
		t.Run(change, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			resource := "https://app.example.invalid/mcp"
			source := &installedJourneyTokenSource{issuer: "https://id.example.invalid/realms/test", resource: resource, now: func() time.Time { return now },
				login: func() kcTokens {
					return kcTokens{Access: installedSchedulingToken(t, now, "developer", resource), Refresh: "original"}
				}}
			original, err := source.Token(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(5 * time.Minute)
			source.refresh = func(string) kcTokens {
				next := kcTokens{Access: installedSchedulingToken(t, now, "developer", resource), Refresh: "rotated"}
				switch change {
				case "subject":
					next.Access = installedSchedulingToken(t, now, "replacement", resource)
				case "audience":
					next.Access = installedSchedulingToken(t, now, "developer", "https://other.invalid/mcp")
				case "issuer":
					source.issuer = "https://other.invalid/realm"
				case "expired":
					next.Access = original
				case "malformed":
					next.Access = "not-a-token"
				case "missing-refresh":
					next.Refresh = ""
				}
				return next
			}
			if token, err := source.Token(t.Context()); err == nil || token != "" {
				t.Fatal("invalid identity supplied to HTTP", change)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	source := &installedJourneyTokenSource{login: func() kcTokens { t.Fatal("cancelled request logged in"); return kcTokens{} }}
	if _, err := source.Token(ctx); err != context.Canceled {
		t.Fatal("lost cancellation", err)
	}
	if err := installedJourneyPause(ctx, time.Hour); err != context.Canceled {
		t.Fatal("sleep ignored cancellation", err)
	}
}

func TestInstalledJourneyChecksCompleteWireFailureAndNeverRetainsMetadata(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"schema_version":"mcp-result/v1","request_id":"00000000-0000-4000-8000-000000000001","data_class":"metadata","status":"error","data":{"code":"NotAvailable","message":"Unavailable","retryable":true},"truncated":false,"next_cursor":null,"narrowing_hint":null,"warnings":[],"provenance":[]}`
	for _, name := range []string{"get_case", "prepare_artifact_download"} {
		reply := &sdk.CallToolResult{StructuredContent: json.RawMessage(raw), IsError: true}
		if got, err := installedJourneyReply(wire, name, reply); err != nil || got.Status != "error" {
			t.Fatal("valid refusal", name, err)
		}
		for _, broken := range []string{`{"status":"error"}`, strings.Replace(raw, "NotAvailable", "InvalidInput", 1), strings.Replace(raw, `"retryable":true`, `"retryable":"true"`, 1)} {
			reply.StructuredContent = json.RawMessage(broken)
			if _, err := installedJourneyReply(wire, name, reply); err == nil {
				t.Fatal("malformed failure counted as authority refusal", name)
			}
		}
		reply.StructuredContent, reply.IsError = json.RawMessage(raw), false
		if _, err := installedJourneyReply(wire, name, reply); err == nil {
			t.Fatal("inconsistent SDK error flag accepted")
		}
	}
	var data struct {
		State    string `json:"state"`
		Continue bool   `json:"continue_preparation"`
		SHA256   string `json:"sha256"`
	}
	if installedJourneyDecode([]byte(`{"state":"Preparing","continue_preparation":true}`), &data) != nil || !data.Continue {
		t.Fatal("acknowledged continuation missing")
	}
	if installedJourneyDecode([]byte(`{"state":"Preparing"}`), &data) != nil || data.Continue {
		t.Fatal("passive status retained continuation permission")
	}
	data.SHA256 = "old-native-digest"
	if installedJourneyDecode([]byte(`{"state":"Failed"}`), &data) != nil || data.SHA256 != "" {
		t.Fatal("terminal response retained previous native metadata")
	}
}
