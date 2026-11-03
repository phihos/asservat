package contracts

import (
	"encoding/json"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"os"
	"testing"
)

// These are provenance representation bounds. The SQL/bootstrap owner must
// independently match the exact embedded release head and bundle digest.
func TestInitialSchemaCanonicalHeadBounds(t *testing.T) {
	for _, name := range []string{"initial-preparation-root", "initial-installer"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile("../../specs/contracts/" + name + ".schema.json")
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err = json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			head := doc["properties"].(map[string]any)["schema"].(map[string]any)["properties"].(map[string]any)["head"].(map[string]any)
			if head["maximum"] != float64(InitialSchemaMaxHead) {
				t.Fatal("canonical and Go provenance bounds differ", head)
			}
			c := jsonschema.NewCompiler()
			if err = c.AddResource("urn:initial-schema-head", head); err != nil {
				t.Fatal(err)
			}
			schema, err := c.Compile("urn:initial-schema-head")
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range []float64{1, 48, 128, 129, 99999} {
				if err = schema.Validate(value); err != nil {
					t.Errorf("schema head %v refused: %v", value, err)
				}
			}
			for _, value := range []float64{-1, 0, 1.5, 100000} {
				if err = schema.Validate(value); err == nil {
					t.Errorf("invalid head %v accepted", value)
				}
			}
		})
	}
}
