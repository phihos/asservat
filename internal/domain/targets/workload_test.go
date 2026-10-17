package targets

import "testing"

func TestWorkloadRequestContainsOnlyNamedPublicScope(t *testing.T) {
	r := WorkloadRequest{ClusterID: "11111111-1111-4111-8111-111111111111", Namespace: "payments", Kind: "Deployment", Name: "checkout"}
	for _, kind := range []string{"Deployment", "StatefulSet", "Pod"} {
		r.Kind = kind
		if !r.Valid() {
			t.Fatalf("supported whole-pod kind rejected: %s", kind)
		}
	}
	for _, mutate := range []func(*WorkloadRequest){
		func(r *WorkloadRequest) { r.ClusterID = "caller-chosen-endpoint" },
		func(r *WorkloadRequest) { r.Namespace = "" },
		func(r *WorkloadRequest) { r.Name = "" },
		func(r *WorkloadRequest) { r.Kind = "Container" },
		func(r *WorkloadRequest) { r.Kind = "ReplicaSet" },
	} {
		changed := r
		mutate(&changed)
		if changed.Valid() {
			t.Fatal("invalid public target accepted")
		}
	}
}
