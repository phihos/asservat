package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// A capture of a workload asks the API server for each of its pods on the
// node at once. With client-go's own limit of 5 requests a second, the
// recordings of 200 pods on one node started 40 seconds late and their logs
// failed with "client rate limiter Wait returned an error".
func TestTheAgentAsksForManyPodsAtOnce(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"kind":"Pod","apiVersion":"v1","metadata":{"name":"one","namespace":"load"}}`)
	}))
	defer server.Close()
	kube, err := kubeClient(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var all sync.WaitGroup
	for range 200 {
		all.Go(func() {
			if _, err := kube.CoreV1().Pods("load").Get(ctx, "one", metav1.GetOptions{}); err != nil {
				t.Error(err)
			}
		})
	}
	all.Wait()
}
