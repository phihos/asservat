package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	coordination "k8s.io/api/coordination/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func TestCapacitySchedulingLeaseRetainsBlockedChildPastFormerShutdownTimer(t *testing.T) {
	// Actual client-go leader callback and local TLS API, with synthetic Lease
	// identity. This qualifies local joining, not distributed fencing.
	lease := coordination.Lease{TypeMeta: meta.TypeMeta{APIVersion: "coordination.k8s.io/v1", Kind: "Lease"}, ObjectMeta: meta.ObjectMeta{Name: "reconcile", Namespace: permissionControl.Name, UID: types.UID(ownerID(1)), ResourceVersion: "1"}}
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-leader" {
			t.Error("unexpected scheduling credential")
		}
		if r.Method == "GET" && r.URL.Path == "/api/v1/namespaces/"+permissionControl.Name {
			permissionReply(w, permissionNamespace(permissionControl.Name, permissionControl.UID))
			return
		}
		if r.URL.Path != "/apis/coordination.k8s.io/v1/namespaces/"+permissionControl.Name+"/leases/reconcile" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "PUT" {
			var v coordination.Lease
			if json.NewDecoder(r.Body).Decode(&v) != nil || v.UID != lease.UID || v.ResourceVersion != lease.ResourceVersion {
				t.Error("scheduling CAS changed")
				http.Error(w, "unavailable", 409)
				return
			}
			v.ResourceVersion = "2"
			lease = v
		} else if r.Method != "GET" {
			t.Error("unexpected scheduling effect")
			http.Error(w, "unavailable", 403)
			return
		}
		permissionReply(w, lease)
	}))
	defer server.Close()
	client, err := NewPermissionClient(&rest.Config{Host: server.URL, BearerToken: "synthetic-leader", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, permissionCluster, permissionControl, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	leader, err := NewReconciliationLeader(client, "reconcile", ownerID(1), ownerID(3))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	done := make(chan error, 1)
	go func() {
		done <- leader.Run(ctx, func(call context.Context) error {
			close(entered)
			<-call.Done()
			close(canceled)
			<-release
			return call.Err()
		})
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("leader failed before original callback", err)
	case <-time.After(5 * time.Second):
		t.Fatal("leader did not start")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("original callback was not canceled")
	}
	select {
	case <-done:
		t.Fatal("leader returned while original callback remained unjoined")
	case <-time.After(7250 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("joined callback did not finish leader shutdown")
	}
}
