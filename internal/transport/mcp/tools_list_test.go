package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// registryOperations advertises every embedded production contract, as a
// fully composed installation does. Discovery is identical for every caller;
// Call is never reached by these tests.
type registryOperations struct {
	origin string
	wire   *contracts.InvestigationContracts
	names  []string
}

func (r registryOperations) PublicOrigin() string { return r.origin }
func (r registryOperations) ToolNames() []string  { return r.names }
func (r registryOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	return r.wire.Tool(name)
}
func (registryOperations) Call(context.Context, identities.CurrentIdentity, string, json.RawMessage) (presentation.OperationReply, error) {
	return presentation.OperationReply{}, errors.New("not callable")
}

func TestToolsListPagesStayWithinResponseLimit(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	names := contracts.InvestigationToolNames()
	mcpTools := map[string]bool{}
	for _, name := range names {
		tool, _ := wire.Tool(name)
		if tool.MCP() {
			mcpTools[name] = true
		}
	}
	var handler *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	handler, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
		return testIdentity(), nil
	}), registryOperations{origin: server.URL, wire: wire, names: names})
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			seen := map[string]int{}
			cursor := ""
			for page := 0; ; page++ {
				if page > len(mcpTools) {
					t.Fatal("tools/list does not terminate")
				}
				params := map[string]any{}
				if cursor != "" {
					params["cursor"] = cursor
				}
				response, b := send(t, server, rpcRequest(t, server, version, "tools/list", params))
				var listed struct {
					Result sdk.ListToolsResult `json:"result"`
				}
				if response.StatusCode != http.StatusOK || json.Unmarshal(b, &listed) != nil {
					t.Fatalf("page %d: status %d, %d bytes", page, response.StatusCode, len(b))
				}
				t.Logf("page %d: %d tools, %d bytes (limit %d)", page, len(listed.Result.Tools), len(b), MaxResponseBytes)
				if len(b) > MaxResponseBytes || len(listed.Result.Tools) == 0 {
					t.Fatalf("page %d: %d bytes, %d tools", page, len(b), len(listed.Result.Tools))
				}
				for _, tool := range listed.Result.Tools {
					seen[tool.Name]++
				}
				if cursor = listed.Result.NextCursor; cursor == "" {
					break
				}
			}
			if len(seen) != len(mcpTools) {
				t.Fatalf("listed %d tools, want %d", len(seen), len(mcpTools))
			}
			for name, count := range seen {
				if count != 1 || !mcpTools[name] {
					t.Fatalf("tool %s listed %d times (registered for MCP: %v)", name, count, mcpTools[name])
				}
			}
		})
	}
}

// A descriptor above the page budget would force an oversized page, so every
// MCP-visible descriptor must fit toolsListBudget on its own.
func TestEveryToolDescriptorFitsOneListPage(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range contracts.InvestigationToolNames() {
		d, _ := wire.Tool(name)
		var annotations sdk.ToolAnnotations
		_ = json.Unmarshal(d.Annotations, &annotations)
		b, err := json.Marshal(&sdk.Tool{Name: name, Description: d.Description, Annotations: &annotations, InputSchema: d.InputSchema, OutputSchema: d.OutputSchema})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %d bytes (mcp=%v)", name, len(b), d.MCP())
		if d.MCP() && len(b) > toolsListBudget {
			t.Errorf("%s descriptor is %d bytes, above the %d byte tools/list page budget", name, len(b), toolsListBudget)
		}
	}
}
