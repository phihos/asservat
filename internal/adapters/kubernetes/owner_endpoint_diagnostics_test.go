package kubernetes

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/client-go/rest"
)

type endpointDiagnosticConfig func(context.Context) (value.OwnerConfigurationObservation, error)

func (f endpointDiagnosticConfig) ReadOwnerConfiguration(ctx context.Context) (value.OwnerConfigurationObservation, error) {
	return f(ctx)
}

func TestOwnerEndpointActualRouteDiagnosticsDistinguishLiveReadAndFinalRVFailure(t *testing.T) {
	for _, mode := range []string{"changed-pod", "http-503"} {
		t.Run(mode, func(t *testing.T) {
			v := ownerFixtureObjects()
			var calls, pods atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				base := "/api/v1/namespaces/" + v.pool.Namespace
				apps := "/apis/apps/v1/namespaces/" + v.pool.Namespace
				var object any
				switch r.URL.Path {
				case base:
					object = v.ns
				case base + "/services/" + v.pool.Service:
					object = v.svc
				case base + "/serviceaccounts/" + v.pool.ServiceAccount:
					object = v.sa
				case apps + "/deployments/" + v.pool.Deployment:
					object = v.deploy
				case apps + "/replicasets/" + v.rs.Name:
					object = v.rs
				case base + "/pods/" + v.pod.Name:
					pod := v.pod.DeepCopy()
					if pods.Add(1) == 2 {
						pod.ResourceVersion = "11"
					}
					object = pod
				case "/apis/discovery.k8s.io/v1/namespaces/" + v.pool.Namespace + "/endpointslices":
					if mode == "http-503" {
						http.Error(w, "private upstream payload", http.StatusServiceUnavailable)
						return
					}
					object = v.list
				default:
					t.Error("unexpected API read", r.URL.Path)
					w.WriteHeader(http.StatusForbidden)
					return
				}
				permissionReply(w, object)
			}))
			defer server.Close()
			client, err := NewPermissionClient(&rest.Config{Host: server.URL, BearerToken: "synthetic-owner", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, v.pool.ClusterID, cfg.NamespaceRef{Name: v.pool.Namespace, UID: v.pool.NamespaceUID}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			endpoints, err := NewOwnerEndpoints(client, v.pool)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			original, _ := ctx.Deadline()
			configs := 0
			routes := app.OwnerRoutes{Endpoints: endpoints, Now: time.Now, Configurations: endpointDiagnosticConfig(func(call context.Context) (value.OwnerConfigurationObservation, error) {
				configs++
				until, finite := call.Deadline()
				if !finite || until.After(original) || call.Err() != nil {
					t.Error("configuration read changed original context")
				}
				now := time.Now()
				return value.OwnerConfigurationObservation{Configuration: value.OwnerConfiguration{Pool: v.pool, Revision: identity.Revision{UID: "source", Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{{3}}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
			})}
			var reports []string
			_, err = routes.CurrentOwnerRoute(app.WithRefusalSteps(ctx, func(step string) { reports = append(reports, step) }), v.binding)
			want, count := "route-read/endpoints/read/pod-final-rv/other@>=2s", int32(9)
			if mode == "http-503" {
				want, count = "route-read/endpoints/read/slices-read/other@>=2s", 5
			}
			if err != value.ErrUnavailable || !reflect.DeepEqual(reports, []string{want}) || configs != 1 || calls.Load() != count || ctx.Err() != nil || !time.Now().Before(original) {
				t.Fatal("failure changed class, read order/count, deadline or closed diagnostic", err, reports, configs, calls.Load(), ctx.Err())
			}
			if strings.Contains(strings.Join(reports, " "), "private upstream") || strings.Contains(strings.Join(reports, " "), v.binding.PodUID) {
				t.Fatal("diagnostic disclosed provider text or identity")
			}
		})
	}
}
