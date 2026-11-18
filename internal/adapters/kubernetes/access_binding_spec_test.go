package kubernetes

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
)

// ADR-237: a proposed spec passes the same schema and checks as an observed
// AccessBinding and carries its canonical spec digest.
func TestAccessBindingSpecDecoder(t *testing.T) {
	d, err := NewAccessBindingSpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	spec := `{"effect":"Deny","subjects":[{"kind":"Group","issuer":"https://id.example.invalid/realms/company","id":"team-a"}],"roles":["evidence-reader"],` +
		`"workloads":[{"kind":"Deployment","name":"api","uid":"wl-uid"}],"reason":"Incident review"}`
	b, err := d.DecodeAccessBindingSpec([]byte(spec))
	if err != nil || b.Effect != "Deny" || len(b.Subjects) != 1 || b.Subjects[0].ID != "team-a" || b.Scope.Namespace.UID != "" || len(b.Scope.Workloads) != 1 || b.Resource.SpecDigest == (artifact.Digest{}) || b.Resource.Kind != "AccessBinding" {
		t.Fatalf("%v %+v", err, b)
	}
	for _, bad := range []string{
		`{"effect":"Deny"}`,
		`{"effect":"Allow","subjects":[{"kind":"Group","issuer":"","id":"team-a"}],"roles":["evidence-reader"],"reason":"x"}`,
		// ADR-329: the old scope field is gone; the namespace is the scope.
		`{"effect":"Allow","subjects":[{"kind":"Group","issuer":"https://id.example.invalid","id":"team-a"}],"roles":["evidence-reader"],"scope":{"clusterID":"00000000-0000-4000-8000-000000000001"},"reason":"x"}`,
		`[]`,
	} {
		if _, err := d.DecodeAccessBindingSpec([]byte(bad)); !errors.Is(err, value.ErrInvalid) {
			t.Fatalf("%s: %v", bad, err)
		}
	}
}

func TestProposedBindingRequiresEverySubjectToFitAdmission(t *testing.T) {
	d, err := NewAccessBindingSpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, id, issuer string
		valid            bool
	}{
		{"256 UTF8 bytes", strings.Repeat("é", 128), "", true},
		{"257 ASCII bytes", strings.Repeat("x", 257), "", false},
		{"258 UTF8 bytes", strings.Repeat("é", 129), "", false},
		{"ID control", "other\x00", "", false},
		{"2048 issuer bytes", "other", strings.Repeat("é", 1024), true},
		{"oversized issuer", "other", strings.Repeat("é", 1025), false},
		{"issuer control", "other", "identity\nissuer", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, effect := range []string{"Allow", "Deny"} {
				second := map[string]string{"kind": "Group", "id": tc.id}
				if tc.issuer != "" {
					second["issuer"] = tc.issuer
				}
				raw, _ := json.Marshal(map[string]any{"effect": effect, "subjects": []map[string]string{{"kind": "Group", "id": "developers"}, second}, "roles": []string{"evidence-reader"}, "reason": "synthetic"})
				b, err := d.DecodeAccessBindingSpec(raw)
				if tc.valid {
					if err != nil || len(b.Subjects) != 2 {
						t.Fatalf("%s: representable proposal lost: %v", effect, err)
					}
				} else if !errors.Is(err, value.ErrInvalid) {
					t.Fatalf("%s: proposal with unrepresentable subject previewed: %v", effect, err)
				}
			}
		})
	}
}
