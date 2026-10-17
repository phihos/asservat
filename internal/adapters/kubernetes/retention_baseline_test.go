package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// ADR-195 D2: the baseline is created once from the operator's values and a
// rerun accepts only the same spec.
func TestRetentionBaselineCreateAndExactReopen(t *testing.T) {
	var stored map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasPrefix(r.URL.Path, "/apis/asservat.io/v1alpha1/namespaces/hub/evidenceretentionpolicies") {
			w.WriteHeader(404)
			return
		}
		if r.Method == http.MethodPost {
			if stored != nil {
				w.WriteHeader(409)
				_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: meta.StatusReasonAlreadyExists, Code: 409})
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&stored)
		}
		_ = json.NewEncoder(w).Encode(stored)
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	b := contracts.InstallerRetentionBaseline{PurposeRef: "synthetic-baseline", Defaults: contracts.InstallerRetentionDurations{EvidenceSeconds: 60, CaseMetadataSeconds: 60, AuditMetadataSeconds: 60},
		Maxima: contracts.InstallerRetentionDurations{EvidenceSeconds: 600, CaseMetadataSeconds: 600, AuditMetadataSeconds: 600}, DeletionBudgetSeconds: 30}
	if err := EnsureRetentionBaseline(context.Background(), config, "hub", ownerID(1), b); err != nil || stored["metadata"].(map[string]any)["name"] != contracts.RetentionBaselineName(ownerID(1)) {
		t.Fatal("baseline create", err)
	}
	spec := stored["spec"].(map[string]any)
	if spec["legalExceptions"] != "disabled" || len(spec["rules"].([]any)) != 0 || len(spec["scope"].(map[string]any)) != 0 {
		t.Fatal("baseline is not an empty-scope policy", spec)
	}
	if err := EnsureRetentionBaseline(context.Background(), config, "hub", ownerID(1), b); err != nil {
		t.Fatal("exact rerun refused", err)
	}
	b.Maxima.EvidenceSeconds = 1200
	if err := EnsureRetentionBaseline(context.Background(), config, "hub", ownerID(1), b); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("changed baseline accepted", err)
	}
}
