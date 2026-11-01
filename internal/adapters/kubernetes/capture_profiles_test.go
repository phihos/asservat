package kubernetes

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/planning"
	value "asservat.local/asservat/internal/domain/targets"
)

type regionProfiles struct{ targets *PodTargets }

func (r regionProfiles) ReadCaptureProfiles(ctx context.Context, q value.ProfileCatalogRequest) (value.ProfileCatalogAnswer, error) {
	return r.targets.ReadCaptureProfiles(ctx, q)
}
func (r regionProfiles) ListCaptureProfiles(ctx context.Context, q value.ProfileListRequest) (value.ProfileCatalogAnswer, error) {
	return r.targets.ListCaptureProfiles(ctx, q)
}

// REQ-CPR-001: namespace profiles are read by the target's region from the
// target's own namespace after binding its UID; a missing version is absent,
// a replaced namespace refuses, and the hub binds the source identities.
func TestNamespaceCaptureProfilesReadInTargetNamespace(t *testing.T) {
	clock := &atomic.Int64{}
	clock.Store(time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC).UnixNano())
	var reads []string
	targets := signalServer(t, clock, func() []any { return nil }, func(w http.ResponseWriter, r *http.Request) bool {
		name, ok := strings.CutPrefix(r.URL.Path, "/apis/asservat.io/v1alpha1/namespaces/payments/captureprofiles/")
		if !ok {
			return false
		}
		reads = append(reads, name)
		if name != "tcp.v1" {
			w.WriteHeader(404)
			permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "reason": "NotFound", "status": "Failure", "code": 404})
			return true
		}
		permissionReply(w, map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "CaptureProfile",
			"metadata": map[string]any{"name": "tcp.v1", "namespace": "payments", "uid": "profile-uid"},
			"spec":     map[string]any{"name": "tcp", "version": "v1", "definition": map[string]any{"displayName": "TCP"}, "availability": map[string]any{"enabled": true, "deprecated": true}}})
		return true
	})
	catalog, err := NewCaptureProfileCatalog(targets.client, cfg.NamespaceRef{Name: "asservat", UID: "hub-ns-uid"}, regionProfiles{targets})
	if err != nil {
		t.Fatal(err)
	}
	target := value.PodResolution{Request: value.Request{ClusterID: permissionCluster, Namespace: cfg.NamespaceRef{Name: "payments", UID: "payments-uid"}}}
	refs := []planning.ProfileRef{{Catalog: "namespace", Name: "tcp", Version: "v1"}, {Catalog: "namespace", Name: "tcp", Version: "v2"}, {Catalog: "builtin", Name: "tcp", Version: "v1"}}
	got, err := catalog.ReadCatalogProfiles(context.Background(), target, refs)
	if err != nil || len(got) != 1 {
		t.Fatalf("read = %+v, %v", got, err)
	}
	p := got[0]
	if p.Ref != refs[0] || p.SourceClusterID != permissionCluster || p.SourceNamespaceUID != "payments-uid" || p.SourceUID != "profile-uid" || !p.Enabled || !p.Deprecated ||
		string(p.Document) != `{"name":"tcp","version":"v1","definition":{"displayName":"TCP"}}` {
		t.Fatalf("profile = %+v %s", p, p.Document)
	}
	if strings.Join(reads, ",") != "tcp.v1,tcp.v2" {
		t.Fatalf("reads = %v", reads)
	}
	target.Request.Namespace.UID = "replaced-uid"
	if _, err := catalog.ReadCatalogProfiles(context.Background(), target, refs); !errors.Is(err, value.ErrChanged) {
		t.Fatalf("replaced namespace: %v", err)
	}
}
