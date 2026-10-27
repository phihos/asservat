// Package manifest validates persistent contracts; it owns no access policy.
package manifest

import (
	"asservat.local/asservat/internal/domain/artifact"
	"bytes"
	"embed"
	"encoding/json"
	"encoding/json/jsontext"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"io"
	"strconv"
)

// Copies of the canonical schemas are generated and checked byte-for-byte.
//
//go:embed schemas/*.json
var schemas embed.FS

type denyLoader struct{}

func (denyLoader) Load(string) (any, error) { return nil, artifact.ErrInvalid }

type Validator struct{ manifest, commit, pod, syscallEvent *jsonschema.Schema }

func New() (*Validator, error) {
	c := jsonschema.NewCompiler()
	c.UseLoader(denyLoader{})
	c.AssertFormat()
	files, err := schemas.ReadDir("schemas")
	if err != nil {
		return nil, artifact.ErrInvalid
	}
	for _, f := range files {
		b, err := schemas.ReadFile("schemas/" + f.Name())
		if err != nil {
			return nil, artifact.ErrInvalid
		}
		var v map[string]any
		if json.Unmarshal(b, &v) != nil {
			return nil, artifact.ErrInvalid
		}
		id, ok := v["$id"].(string)
		if !ok || c.AddResource(id, v) != nil {
			return nil, artifact.ErrInvalid
		}
	}
	var v Validator
	for _, pair := range []struct {
		id  string
		out **jsonschema.Schema
	}{{"manifest.schema.json", &v.manifest}, {"framed-storage.schema.json#/$defs/commit", &v.commit}, {"pod-status.schema.json", &v.pod}, {"syscall-results.schema.json#/$defs/event", &v.syscallEvent}} {
		*pair.out, err = c.Compile("https://asservat.io/spec/v1/" + pair.id)
		if err != nil {
			return nil, artifact.ErrInvalid
		}
	}
	return &v, nil
}

// Strict syntax before schema evaluation bounds tree construction, numeric
// arithmetic and nested uniqueItems work. Errors never contain input content.
// This profile contains only integer JSON numbers; future profiles are separate.
func strict(b []byte, limit int64) (any, error) {
	if len(b) == 0 || int64(len(b)) > limit {
		return nil, artifact.ErrLimit
	}
	d := jsontext.NewDecoder(bytes.NewReader(b))
	for tokens := 0; ; tokens++ {
		t, err := d.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, artifact.ErrInvalid
		}
		if tokens >= 32768 || d.StackDepth() > 32 {
			return nil, artifact.ErrLimit
		}
		if t.Kind() == '0' {
			n := t.String()
			if len(n) > 20 {
				return nil, artifact.ErrLimit
			}
			if _, err := strconv.ParseInt(n, 10, 64); err != nil {
				return nil, artifact.ErrInvalid
			}
		}
	}
	// jsonschema.UnmarshalJSON retains exact numbers and rejects trailing values.
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return nil, artifact.ErrInvalid
	}
	return v, nil
}

func validate(s *jsonschema.Schema, b []byte, limit int64) error {
	v, err := strict(b, limit)
	if err != nil {
		return err
	}
	if s.Validate(v) != nil {
		return artifact.ErrInvalid
	}
	return nil
}
