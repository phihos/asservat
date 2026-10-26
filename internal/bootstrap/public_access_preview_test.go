package bootstrap

import (
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// ADR-237: installed delegation envelopes with browser previewers become the
// preview's delegated authority; an invalid entry stops the composition.
func TestPreviewDelegationsFromInstalledEnvelopes(t *testing.T) {
	d := contracts.PermissionDelegation{Writers: []contracts.OwnerDeploymentActor{{Kind: "Group", Name: "payments-admins"}}, ClusterID: "00000000-0000-4000-8000-000000000001",
		Namespace: contracts.WorkerObjectReference{Name: "payments", UID: "ns-uid"}, Workloads: []contracts.PermissionWorkload{{Kind: "Deployment", Name: "api", UID: "wl-uid"}},
		Roles: []string{"evidence-reader"}, Issuers: []string{"https://id.example.invalid"},
		Previewers: []contracts.PermissionPreviewer{{Issuer: "https://id.example.invalid", Kind: "Group", ID: "payments-leads"}}}
	got, err := previewDelegations([]contracts.PermissionDelegation{d})
	if err != nil || len(got) != 1 || got[0].Envelope.Scope.Namespace.UID != "ns-uid" || len(got[0].Envelope.Scope.Workloads) != 1 || got[0].Previewers[0].ID != "payments-leads" {
		t.Fatalf("%v %+v", err, got)
	}
	for _, bad := range []func(*contracts.PermissionDelegation){
		func(x *contracts.PermissionDelegation) { x.Previewers = nil },
		func(x *contracts.PermissionDelegation) { x.Previewers[0].Kind = "Workload" },
		func(x *contracts.PermissionDelegation) { x.ClusterID = "not-a-uuid" },
		func(x *contracts.PermissionDelegation) { x.Roles = nil },
	} {
		x := d
		x.Previewers = append([]contracts.PermissionPreviewer(nil), d.Previewers...)
		bad(&x)
		if _, err := previewDelegations([]contracts.PermissionDelegation{x}); err == nil {
			t.Fatalf("accepted %+v", x)
		}
	}
}
