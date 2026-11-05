package presentation

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type profileOperationFixture struct {
	*contextOperationFixture
	catalog string
}

func (f *profileOperationFixture) CaptureProfiles(_ context.Context, _ identities.CurrentIdentity, _ targets.WorkloadRequest, catalog string) ([]compiler.ProfileDescription, time.Time, error) {
	f.catalog = catalog
	return compiler.DescribeProfiles(catalog, nil), f.metadataUntil, f.err
}
func (f *profileOperationFixture) CaptureProfile(_ context.Context, _ identities.CurrentIdentity, _ targets.WorkloadRequest, ref planning.ProfileRef) (compiler.ProfileDescription, time.Time, error) {
	for _, p := range compiler.DescribeProfiles(ref.Catalog, nil) {
		if p.Ref == ref {
			return p, f.metadataUntil, f.err
		}
	}
	return compiler.ProfileDescription{}, time.Time{}, value.ErrProfileNotFound
}

// REQ-CPR-001: both profile tools pass the runtime contract for browser and
// MCP: the list is metadata, the definition read is an extract, and an
// unpublished version is a closed ProfileNotFound error.
func TestCaptureProfileToolsProjectContract(t *testing.T) {
	base, inner := operationFixture(t, false)
	f := &profileOperationFixture{contextOperationFixture: inner}
	s, err := NewContextOperations(base.config, f, f)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := s.Call(context.Background(), f, "list_capture_profiles", []byte(`{`+wireTarget+`,"catalog":"builtin"}`))
	var out struct {
		DataClass string `json:"data_class"`
		Data      struct {
			Profiles []ProfileRow `json:"profiles"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(reply.Body, &out) != nil || out.DataClass != "metadata" || len(out.Data.Profiles) != 4 || f.catalog != "builtin" || out.Data.Profiles[0].ExecutionModes[0] != "onTrigger" {
		t.Fatalf("list = %s, %v", reply.Body, err)
	}
	var names []string
	for _, profile := range out.Data.Profiles {
		names = append(names, profile.Ref.Name)
	}
	if !slices.Equal(names, []string{"network-connections", "syscall-activity", "go-cpu", "finite-logs"}) {
		t.Fatal("actual closed builtin catalog", names)
	}
	reply, err = s.Call(context.Background(), f, "get_capture_profile", []byte(`{`+wireTarget+`,"profile_ref":{"catalog":"builtin","name":"network-connections","version":"v1"}}`))
	if err != nil || !bytes.Contains(reply.Body, []byte(`"data_class":"extract"`)) || !bytes.Contains(reply.Body, []byte(`"definition_digest"`)) {
		t.Fatalf("get = %s, %v", reply.Body, err)
	}
	reply, err = s.Call(context.Background(), f, "get_capture_profile", []byte(`{`+wireTarget+`,"profile_ref":{"catalog":"organization","name":"absent","version":"v1"}}`))
	if err != nil || !bytes.Contains(reply.Body, []byte(`"ProfileNotFound"`)) {
		t.Fatalf("absent = %s, %v", reply.Body, err)
	}
	if _, ok := base.Tool("list_capture_profiles"); ok {
		t.Fatal("a service without catalog reads served the profile tools")
	}
}

func TestRawLogCaptureProfileAdvertisesTypedEdits(t *testing.T) {
	base, inner := operationFixture(t, false)
	f := &profileOperationFixture{contextOperationFixture: inner}
	s, err := NewContextOperations(base.config, f, f)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := s.Call(t.Context(), f, "get_capture_profile", []byte(`{`+wireTarget+`,"profile_ref":{"catalog":"builtin","name":"finite-logs","version":"v1"}}`))
	if err != nil || s.contracts.ValidateOutput("get_capture_profile", reply.Body) != nil {
		t.Fatal("actual builtin logs definition rejected", err, string(reply.Body))
	}
	var out struct {
		Data struct {
			Definition struct {
				Fields []struct {
					Field string `json:"field"`
				} `json:"editableFields"`
			} `json:"definition"`
		} `json:"data"`
	}
	if json.Unmarshal(reply.Body, &out) != nil {
		t.Fatal("actual logs definition")
	}
	fields := map[string]bool{}
	for _, field := range out.Data.Definition.Fields {
		fields[field.Field] = true
	}
	if !fields["logBefore"] || !fields["logAfter"] || !fields["logStream"] {
		t.Fatal("public catalog lost exact declared log edits", fields)
	}
}
