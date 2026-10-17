package contracts

import (
	"bytes"
	"embed"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed investigation-schemas/*.json
var investigationSchemas embed.FS

var ErrInvestigationWire = errors.New("invalid investigation message")

const InvestigationInputLimit = 32 << 10

// MCP carries the JSON both as structured content and compatibility text. This
// bound leaves room for both copies inside the 64 KiB transport response limit.
const InvestigationOutputLimit = 24 << 10

type InvestigationTool struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Annotations  json.RawMessage `json:"annotations"`
	InputSchema  json.RawMessage `json:"inputSchema"`
	OutputSchema json.RawMessage `json:"outputSchema"`
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

func NewInvestigationContracts() (*InvestigationContracts, error) {
	v := &InvestigationContracts{tools: make(map[string]investigationSchema)}
	for _, name := range []string{"list_diagnostics", "preview_capture", "request_capture", "resolve_capture_request", "get_capture", "get_case", "prepare_artifact_download", "get_artifact_download", "cancel_artifact_download"} {
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
	if v == nil {
		return ErrInvestigationWire
	}
	s, ok := v.tools[name]
	if !ok {
		return ErrInvestigationWire
	}
	limit, schema := InvestigationInputLimit, s.input
	if output {
		limit, schema = InvestigationOutputLimit, s.output
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
func (v *InvestigationContracts) ValidateOutput(name string, b []byte) error {
	return v.validate(name, b, true)
}
