package feasibility

import (
	"encoding/json"
	"fmt"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"os"
	"path/filepath"
	"testing"
)

type noRemote struct{}

func (noRemote) Load(url string) (any, error) {
	return nil, fmt.Errorf("remote schema denied: %s", url)
}

func TestCanonicalContracts(t *testing.T) {
	c := jsonschema.NewCompiler()
	c.UseLoader(noRemote{})
	c.AssertFormat()
	paths, e := filepath.Glob("../../../specs/contracts/*.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	if len(paths) != 41 {
		t.Fatalf("update measured corpus count: %d", len(paths))
	}
	ids := make([]string, 0, len(paths))
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		var v map[string]any
		if e = json.Unmarshal(b, &v); e != nil {
			t.Fatal(e)
		}
		id := v["$id"].(string)
		ids = append(ids, id)
		if e = c.AddResource(id, v); e != nil {
			t.Fatal(e)
		}
	}
	for _, id := range ids {
		if _, e = c.Compile(id); e != nil {
			t.Fatalf("compile %s: %v", id, e)
		}
	}
	s, e := c.Compile("https://asservat.io/spec/v1/manifest.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile("../../../examples/manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	if e = s.Validate(v); e != nil {
		t.Fatal(e)
	}
	v["notInContract"] = true
	if e = s.Validate(v); e == nil {
		t.Fatal("unknown property accepted")
	}
	delete(v, "notInContract")
	v["artifactID"] = "not-a-uuid"
	if e = s.Validate(v); e == nil {
		t.Fatal("bad UUID accepted")
	}
	if _, e = c.Compile("https://invalid.example/missing.json"); e == nil {
		t.Fatal("remote load allowed")
	}
	t.Logf("compiled %d canonical schemas offline; manifest positive, unknown property and UUID negatives", len(paths))
}
