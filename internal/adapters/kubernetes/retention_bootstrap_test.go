package kubernetes

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
)

func TestRetentionBootstrapPinsCompleteSnapshotAndProtection(t *testing.T) {
	for _, mode := range []string{"valid", "replaced", "namespace-replaced", "expired", "future", "overlong", "extra-field", "missing-reviewer", "wrong-format", "bad-digest", "zero-protection", "deleting", "slow"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
			guard := artifact.Digest{4}
			data := map[string]string{"format": "asservat-retention-bootstrap/v1", "reviewer": "installation-admin", "policiesSHA256": strings.Repeat("01", 32), "protectionSHA256": hex.EncodeToString(guard[:]), "reviewedAt": now.Add(-time.Minute).Format(time.RFC3339), "expiresAt": now.Add(30 * time.Minute).Format(time.RFC3339)}
			metadata := map[string]any{"name": "retention-bootstrap", "namespace": permissionControl.Name, "uid": "retention-review", "resourceVersion": "review:1"}
			switch mode {
			case "replaced":
				metadata["uid"] = "replacement"
			case "deleting":
				metadata["deletionTimestamp"] = now.Format(time.RFC3339)
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
			case "wrong-format":
				data["format"] = "asservat-permission-bootstrap/v1"
			case "bad-digest":
				data["protectionSHA256"] = "oops"
			case "zero-protection":
				data["protectionSHA256"] = strings.Repeat("00", 32)
			}
			var f permissionFixture
			readReview := false
			f = newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if strings.HasSuffix(r.URL.Path, "/evidenceretentionpolicies") {
					permissionReply(w, permissionList("EvidenceRetentionPolicy", "opaque:list", "", retentionObject("baseline", "retention-uid")))
					return true
				}
				if strings.HasSuffix(r.URL.Path, "/configmaps/retention-bootstrap") {
					readReview = true
					if mode == "slow" {
						f.clock.Add(int64(6 * time.Second))
					}
					permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata, "data": data})
					return true
				}
				if mode == "namespace-replaced" && readReview && r.URL.Path == "/api/v1/namespaces/asservat-system" {
					permissionReply(w, permissionNamespace(permissionControl.Name, "replacement"))
					return true
				}
				return false
			})
			client, err := NewRetentionClient(f.client, true)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := client.RetentionSnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			digest := port.RetentionSnapshotDigest(snapshot)
			data["policiesSHA256"] = hex.EncodeToString(digest[:])
			reader, err := NewRetentionBootstrapReviewClient(f.client, "retention-bootstrap", "retention-review")
			if err != nil {
				t.Fatal(err)
			}
			review, err := reader.InitialRetentionReview(context.Background())
			if mode != "valid" {
				if err == nil {
					t.Fatal("invalid review accepted")
				}
				return
			}
			if err != nil || port.CheckInitialRetention(snapshot, guard, &review, now) != nil {
				t.Fatal("review rejected", err)
			}
		})
	}
}
