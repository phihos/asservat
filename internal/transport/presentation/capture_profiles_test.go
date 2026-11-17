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

// REQ-CPR-001: list_diagnostics lists the preset and the catalog profiles
// (metadata, paginated), get_capture_profile reads a definition (extract) and
// an unpublished version is a closed ProfileNotFound error.
func TestCaptureProfileToolsProjectContract(t *testing.T) {
	base, inner := operationFixture(t, false)
	f := &profileOperationFixture{contextOperationFixture: inner}
	s, err := NewContextOperations(base.config, f, f)
	if err != nil {
		t.Fatal(err)
	}
	type page struct {
		DataClass  string  `json:"data_class"`
		NextCursor *string `json:"next_cursor"`
		Data       struct {
			Diagnostics []DiagnosticRow `json:"diagnostics"`
		} `json:"data"`
	}
	reply, err := s.Call(t.Context(), f, "list_diagnostics", []byte(`{`+wireTarget+`,"catalog":"builtin","limit":3}`))
	var out page
	if err != nil || json.Unmarshal(reply.Body, &out) != nil || out.DataClass != "metadata" || len(out.Data.Diagnostics) != 3 || f.catalog != "builtin" || out.NextCursor == nil || out.Data.Diagnostics[0].ExecutionModes[0] != "onTrigger" {
		t.Fatalf("list = %s, %v", reply.Body, err)
	}
	var names []string
	for _, row := range out.Data.Diagnostics {
		names = append(names, row.Profile.Name)
	}
	reply, err = s.Call(t.Context(), f, "list_diagnostics", []byte(`{`+wireTarget+`,"catalog":"builtin","cursor":"`+*out.NextCursor+`"}`))
	out = page{}
	if err != nil || json.Unmarshal(reply.Body, &out) != nil || out.NextCursor != nil || len(out.Data.Diagnostics) != 1 {
		t.Fatalf("second page = %s, %v", reply.Body, err)
	}
	names = append(names, out.Data.Diagnostics[0].Profile.Name)
	if !slices.Equal(names, []string{"network-connections", "syscall-activity", "go-cpu", "finite-logs"}) {
		t.Fatal("actual closed builtin catalog", names)
	}
	reply, err = s.Call(t.Context(), f, "list_diagnostics", []byte(`{`+wireTarget+`}`))
	out = page{}
	if err != nil || json.Unmarshal(reply.Body, &out) != nil || len(out.Data.Diagnostics) != 5 || out.Data.Diagnostics[0].Kind != "preset" || out.Data.Diagnostics[1].Kind != "captureProfile" {
		t.Fatalf("all = %s, %v", reply.Body, err)
	}
	reply, err = s.Call(t.Context(), f, "list_diagnostics", []byte(`{`+wireTarget+`,"goal":"crash"}`))
	if err != nil || !bytes.Contains(reply.Body, []byte(`"CapabilityUnavailable"`)) {
		t.Fatalf("goal = %s, %v", reply.Body, err)
	}
	reply, err = s.Call(t.Context(), f, "get_capture_profile", []byte(`{`+wireTarget+`,"profile_ref":{"catalog":"builtin","name":"network-connections","version":"v1"}}`))
	if err != nil || !bytes.Contains(reply.Body, []byte(`"data_class":"extract"`)) || !bytes.Contains(reply.Body, []byte(`"definition_digest"`)) {
		t.Fatalf("get = %s, %v", reply.Body, err)
	}
	reply, err = s.Call(t.Context(), f, "get_capture_profile", []byte(`{`+wireTarget+`,"profile_ref":{"catalog":"organization","name":"absent","version":"v1"}}`))
	if err != nil || !bytes.Contains(reply.Body, []byte(`"ProfileNotFound"`)) {
		t.Fatalf("absent = %s, %v", reply.Body, err)
	}
	if _, ok := base.Tool("get_capture_profile"); ok {
		t.Fatal("a service without catalog reads served get_capture_profile")
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

func TestUnknownClusterNameIsADomainError(t *testing.T) {
	s, f := operationFixture(t, false)
	for _, name := range []string{"list_diagnostics", "preview_capture"} {
		in := `{"target_ref":{"cluster":"elsewhere","namespace":"payments","kind":"Deployment","name":"api"}}`
		if name == "preview_capture" {
			in = `{"target_ref":{"cluster":"elsewhere","namespace":"payments","kind":"Deployment","name":"api"},"preset_ref":{"name":"pod-status","version":"v1"}}`
		}
		reply, err := s.Call(t.Context(), f, name, []byte(in))
		if err != nil || !bytes.Contains(reply.Body, []byte(`"code":"UnknownCluster"`)) {
			t.Fatal(name, err, string(reply.Body))
		}
	}
}
