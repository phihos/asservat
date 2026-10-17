package kubernetes

import (
	"context"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	value "asservat.local/asservat/internal/domain/configuration"
)

func TestBootstrapReviewPinsProtectedObjectAndFiniteCompleteSnapshot(t *testing.T) {
	for _, mode := range []string{"valid", "replaced", "expired", "future", "overlong", "extra-field", "missing-reviewer"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
			data := map[string]string{"format": "asservat-permission-bootstrap/v1", "reviewer": "qualified-installation-admin", "bindingsSHA256": hex.EncodeToString(make([]byte, 32)), "reviewedAt": now.Add(-time.Minute).Format(time.RFC3339), "expiresAt": now.Add(30 * time.Minute).Format(time.RFC3339)}
			id := "bootstrap-uid"
			switch mode {
			case "replaced":
				id = "other-uid"
			case "expired":
				data["expiresAt"] = now.Format(time.RFC3339)
			case "future":
				data["reviewedAt"] = now.Add(time.Second).Format(time.RFC3339)
			case "overlong":
				data["expiresAt"] = now.Add(2 * time.Hour).Format(time.RFC3339)
			case "extra-field":
				data["authority"] = "true"
			case "missing-reviewer":
				delete(data, "reviewer")
			}
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/asservat-system/configmaps/permission-bootstrap" {
					return false
				}
				permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "permission-bootstrap", "namespace": permissionControl.Name, "uid": id, "resourceVersion": "review-rv"}, "data": data})
				return true
			})
			snapshot, err := f.client.PermissionSnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			hash := port.InitialBindingDigest(snapshot)
			data["bindingsSHA256"] = hex.EncodeToString(hash[:])
			reader, err := NewBootstrapReviewClient(f.client, "permission-bootstrap", "bootstrap-uid")
			if err != nil {
				t.Fatal(err)
			}
			review, err := reader.InitialPermissionReview(context.Background())
			if mode != "valid" {
				if err == nil {
					t.Fatal("invalid bootstrap review trusted")
				}
				return
			}
			if err != nil || port.CheckInitialBindings(snapshot, &review, now) != nil {
				t.Fatalf("review rejected %v", err)
			}
			changed := snapshot
			changed.Bindings = append([]value.Binding{}, snapshot.Bindings...)
			changed.Bindings[0].Resource.UID = "replacement"
			if port.CheckInitialBindings(changed, &review, now) == nil {
				t.Fatal("review covered a replacement binding")
			}
		})
	}
}
