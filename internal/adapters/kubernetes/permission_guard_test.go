package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func TestGuardProofPreservesStructuredAdmissionCause(t *testing.T) {
	for _, code := range []int{403, 422} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			cause := "exact synthetic enforcing-policy cause"
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Query().Get("dryRun") != "All" {
					t.Error("unexpected proof request")
				}
				reason := metav1.StatusReasonForbidden
				if code == 422 {
					reason = metav1.StatusReasonInvalid
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: reason, Code: int32(code), Message: "synthetic denial", Details: &metav1.StatusDetails{Group: "asservat.io", Kind: "accessbindings", Causes: []metav1.StatusCause{{Message: cause}}}})
			}))
			defer server.Close()
			c, err := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, permissionCluster, permissionControl, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.proofPost(context.Background(), "/proof", map[string]string{"kind": "synthetic"}, map[string]string{"dryRun": "All"})
			var status apierrors.APIStatus
			if !errors.As(err, &status) {
				t.Fatalf("structured denial missing: %v", err)
			}
			details := status.Status().Details
			if details == nil || details.Group != "asservat.io" || details.Kind != "accessbindings" || len(details.Causes) != 1 || details.Causes[0].Message != cause {
				t.Fatalf("admission cause lost: %+v", details)
			}
		})
	}
}
