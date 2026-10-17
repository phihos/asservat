package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	coordination "k8s.io/api/coordination/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/utils/ptr"
)

func TestReconciliationLeasePinsAndNoCreation(t *testing.T) {
	for _, mode := range []string{"valid", "replacement", "deleting", "excess-duration", "coordinated", "bad-resource-version"} {
		t.Run(mode, func(t *testing.T) {
			var writes atomic.Int32
			lease := coordination.Lease{TypeMeta: meta.TypeMeta{APIVersion: "coordination.k8s.io/v1", Kind: "Lease"}, ObjectMeta: meta.ObjectMeta{Name: "reconcile", Namespace: permissionControl.Name, UID: types.UID(ownerID(1)), ResourceVersion: "1"}}
			switch mode {
			case "replacement":
				lease.UID = types.UID(ownerID(2))
			case "deleting":
				now := meta.Now()
				lease.DeletionTimestamp = &now
			case "excess-duration":
				lease.Spec.LeaseDurationSeconds = ptr.To(int32(3600))
			case "coordinated":
				lease.Spec.PreferredHolder = ptr.To("other")
			case "bad-resource-version":
				lease.ResourceVersion = ""
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer synthetic-leader" {
					t.Error("unexpected lease credential")
				}
				if r.Method == "GET" && r.URL.Path == "/api/v1/namespaces/"+permissionControl.Name {
					permissionReply(w, permissionNamespace(permissionControl.Name, permissionControl.UID))
					return
				}
				if r.URL.Path != "/apis/coordination.k8s.io/v1/namespaces/"+permissionControl.Name+"/leases/reconcile" {
					t.Error("unexpected lease path")
					http.NotFound(w, r)
					return
				}
				if r.Method == "PUT" {
					writes.Add(1)
					var v coordination.Lease
					if r.URL.Query().Get("fieldValidation") != "Strict" || json.NewDecoder(r.Body).Decode(&v) != nil || v.ResourceVersion != "1" || v.UID != types.UID(ownerID(1)) || v.Spec.HolderIdentity == nil || *v.Spec.HolderIdentity != ownerID(3) {
						t.Error("lease update lost pinned identity or CAS")
					}
					v.ResourceVersion = "2"
					permissionReply(w, v)
					return
				}
				if r.Method != "GET" {
					t.Error("unexpected lease effect")
				}
				permissionReply(w, lease)
			}))
			defer server.Close()
			client, err := NewPermissionClient(&rest.Config{Host: server.URL, BearerToken: "synthetic-leader", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, permissionCluster, permissionControl, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			s, err := NewReconciliationLeader(client, "reconcile", ownerID(1), ownerID(3))
			if err != nil {
				t.Fatal(err)
			}
			r, _, err := s.lock.Get(context.Background())
			if mode != "valid" {
				if err == nil {
					t.Fatal("unqualified lease accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			r.HolderIdentity = ownerID(3)
			r.LeaseDurationSeconds = 15
			if err = s.lock.Update(context.Background(), *r); err != nil {
				t.Fatal(err)
			}
			if writes.Load() != 1 {
				t.Fatal("missing CAS update")
			}
			if err = s.lock.Create(context.Background(), resourcelock.LeaderElectionRecord{}); err == nil {
				t.Fatal("runtime can create scheduling identity")
			}
		})
	}
}
