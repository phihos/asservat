package kubernetes

import (
	"errors"
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
		`"scope":{"clusterID":"00000000-0000-4000-8000-000000000001","namespaceRef":{"name":"payments","uid":"ns-uid"},"workloads":[{"kind":"Deployment","name":"api","uid":"wl-uid"}]},"reason":"Incident review"}`
	b, err := d.DecodeAccessBindingSpec([]byte(spec))
	if err != nil || b.Effect != "Deny" || len(b.Subjects) != 1 || b.Subjects[0].ID != "team-a" || b.Scope.Namespace.UID != "ns-uid" || len(b.Scope.Workloads) != 1 || b.Resource.SpecDigest == (artifact.Digest{}) || b.Resource.Kind != "AccessBinding" {
		t.Fatalf("%v %+v", err, b)
	}
	for _, bad := range []string{
		`{"effect":"Deny"}`,
		`{"effect":"Allow","subjects":[{"kind":"Group","issuer":"http://id.example.invalid","id":"team-a"}],"roles":["evidence-reader"],"scope":{"clusterID":"00000000-0000-4000-8000-000000000001","namespaceRef":{"name":"payments","uid":"ns-uid"}},"reason":"x"}`,
		`[]`,
	} {
		if _, err := d.DecodeAccessBindingSpec([]byte(bad)); !errors.Is(err, value.ErrInvalid) {
			t.Fatalf("%s: %v", bad, err)
		}
	}
}
