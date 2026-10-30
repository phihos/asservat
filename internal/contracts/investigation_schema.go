package contracts

import (
	"bytes"
	"embed"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
	"slices"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed investigation-schemas/*.json
var investigationSchemas embed.FS

var ErrInvestigationWire = errors.New("invalid investigation message")

const InvestigationInputLimit = 32 << 10

// MCP carries the JSON both as structured content and compatibility text. This
// bound leaves room for both copies inside the 64 KiB transport response limit.
const InvestigationOutputLimit = 24 << 10

// The sole browser settings budget; audit independently bounds its minimized
// output byte count. Wire contracts do not import domain behavior.
const InvestigationBrowserSettingsOutputLimit = 160 << 10

type InvestigationTool struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Annotations  json.RawMessage `json:"annotations"`
	InputSchema  json.RawMessage `json:"inputSchema"`
	OutputSchema json.RawMessage `json:"outputSchema"`
	// Transports restricts an operation to the listed transports; absent, it
	// is served to both the browser and MCP. ADR-237: the administrator's
	// impact preview is browser-only, since REQ-PER-002 adds no admin tool
	// to evidence MCP.
	Transports []string `json:"transports,omitempty"`
}

// MCP reports whether the operation may be listed and called over MCP.
func (t InvestigationTool) MCP() bool {
	return len(t.Transports) == 0 || slices.Contains(t.Transports, "mcp")
}

type investigationSchema struct {
	description   InvestigationTool
	input, output *jsonschema.Schema
}

type InvestigationContracts struct {
	tools map[string]investigationSchema
}
type investigationOfflineLoader struct{}

func (investigationOfflineLoader) Load(string) (any, error) { return nil, ErrInvestigationWire }

// InvestigationToolNames lists every embedded operation contract.
func InvestigationToolNames() []string {
	return []string{"cancel_capture", "list_recordings", "preview_recording_save", "list_diagnostics", "preview_capture", "request_capture", "resolve_capture_request", "get_capture", "get_case", "prepare_artifact_download", "get_artifact_download", "cancel_artifact_download", "get_file_excerpt", "get_query_result", "activate_policy", "get_policy_status", "deactivate_policy", "create_share", "list_shares", "revoke_share", "explain_access", "list_capture_history", "get_capture_settings", "preview_access_change", "transfer_share", "stop_future_sharing", "preview_retention_change", "request_policy_grant", "get_grant", "list_reviews", "decide_review", "revoke_grant"}
}

func NewInvestigationContracts() (*InvestigationContracts, error) {
	v := &InvestigationContracts{tools: make(map[string]investigationSchema)}
	for _, name := range InvestigationToolNames() {
		b, err := investigationSchemas.ReadFile("investigation-schemas/" + name + ".json")
		var d InvestigationTool
		if err != nil || json.Unmarshal(b, &d) != nil || d.Name != name {
			return nil, ErrInvestigationWire
		}
		s := investigationSchema{description: d}
		for _, pair := range []struct {
			raw    []byte
			target **jsonschema.Schema
		}{{d.InputSchema, &s.input}, {d.OutputSchema, &s.output}} {
			c := jsonschema.NewCompiler()
			c.UseLoader(investigationOfflineLoader{})
			c.AssertFormat()
			parsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(pair.raw))
			if err != nil || c.AddResource("urn:asservat:investigation", parsed) != nil {
				return nil, ErrInvestigationWire
			}
			*pair.target, err = c.Compile("urn:asservat:investigation")
			if err != nil {
				return nil, ErrInvestigationWire
			}
		}
		v.tools[name] = s
	}
	return v, nil
}

func (v *InvestigationContracts) Tool(name string) (InvestigationTool, bool) {
	if v == nil {
		return InvestigationTool{}, false
	}
	s, ok := v.tools[name]
	d := s.description
	d.InputSchema, d.OutputSchema, d.Annotations = bytes.Clone(d.InputSchema), bytes.Clone(d.OutputSchema), bytes.Clone(d.Annotations)
	d.Transports = slices.Clone(d.Transports)
	return d, ok
}

// Bound syntax before constructing a schema tree. jsontext rejects duplicate
// members, invalid UTF-8 and malformed JSON. Schema keys remain case sensitive.
func investigationJSON(b []byte, limit int) (any, error) {
	if len(b) == 0 || len(b) > limit {
		return nil, ErrInvestigationWire
	}
	d := jsontext.NewDecoder(bytes.NewReader(b))
	for count := 0; ; count++ {
		_, err := d.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil || count >= 16384 || d.StackDepth() > 32 {
			return nil, ErrInvestigationWire
		}
	}
	out, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return nil, ErrInvestigationWire
	}
	return out, nil
}

func (v *InvestigationContracts) validate(name string, b []byte, output bool) error {
	limit := InvestigationInputLimit
	if output {
		limit = InvestigationOutputLimit
	}
	return v.validateBound(name, b, output, limit)
}

func (v *InvestigationContracts) validateBound(name string, b []byte, output bool, limit int) error {
	if v == nil {
		return ErrInvestigationWire
	}
	s, ok := v.tools[name]
	if !ok {
		return ErrInvestigationWire
	}
	schema := s.input
	if output {
		schema = s.output
	}
	out, err := investigationJSON(b, limit)
	if err != nil || schema.Validate(out) != nil {
		return ErrInvestigationWire
	}
	return nil
}

func (v *InvestigationContracts) ValidateInput(name string, b []byte) error {
	return v.validate(name, b, false)
}

// ValidateBrowserOutput uses the identical canonical schema. Only this fixed
// server-owned operation has a larger browser body; MCP uses ValidateOutput.
func (v *InvestigationContracts) ValidateBrowserOutput(name string, b []byte) error {
	if name == "get_capture_settings" {
		return v.validateBound(name, b, true, InvestigationBrowserSettingsOutputLimit)
	}
	return v.ValidateOutput(name, b)
}
func (v *InvestigationContracts) ValidateOutput(name string, b []byte) error {
	if err := v.validate(name, b, true); err != nil {
		return err
	}
	if name != "get_file_excerpt" && name != "get_query_result" {
		return nil
	}
	var out struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
		Data      struct {
			ObservedAt time.Time       `json:"query_observed_at"`
			ExpiresAt  time.Time       `json:"query_expires_at"`
			Tool       string          `json:"tool_name"`
			Result     json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &out) != nil {
		return ErrInvestigationWire
	}
	if out.Status == "error" {
		return nil
	}
	if out.Data.ObservedAt.IsZero() || !out.Data.ExpiresAt.After(out.Data.ObservedAt) || out.Data.ExpiresAt.Sub(out.Data.ObservedAt) > time.Minute {
		return ErrInvestigationWire
	}
	if name != "get_query_result" || out.Status != "ok" {
		return nil
	}
	// The server-selected original tool is closed at this implementation
	// boundary. A future catalog entry cannot choose a weaker nested schema.
	if out.Data.Tool != "get_file_excerpt" || v.ValidateOutput(out.Data.Tool, out.Data.Result) != nil {
		return ErrInvestigationWire
	}
	var nested struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
		Data      struct {
			ObservedAt time.Time `json:"query_observed_at"`
			ExpiresAt  time.Time `json:"query_expires_at"`
		} `json:"data"`
	}
	if json.Unmarshal(out.Data.Result, &nested) != nil || nested.Status != "ok" || nested.RequestID != out.RequestID || !nested.Data.ObservedAt.Equal(out.Data.ObservedAt) || !nested.Data.ExpiresAt.Equal(out.Data.ExpiresAt) {
		return ErrInvestigationWire
	}
	return nil
}
