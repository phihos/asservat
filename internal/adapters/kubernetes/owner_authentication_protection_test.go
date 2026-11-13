package kubernetes

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

type ownerAuthRegistry func(context.Context, value.OwnerCertificate) (value.OwnerRegistrationObservation, error)

func (f ownerAuthRegistry) ReadOwnerRegistration(c context.Context, x value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	return f(c, x)
}

type ownerAuthPeer struct{ certificate value.OwnerCertificate }

func (p ownerAuthPeer) OwnerCertificate() (value.OwnerCertificate, error) { return p.certificate, nil }
func (p ownerAuthPeer) VerifyCurrentOwner(value.OwnerConfigurationObservation) (value.OwnerCertificate, error) {
	return p.certificate, nil
}

// Helm-native installation (2026-11-13): peer authentication composes SQL
// registration, the live Ready Pod → ReplicaSet → Deployment route and the TLS
// certificate with the real workload protection, and no admission policy,
// binding, probe identity or dry-run request exists. A wrong Pod chain still
// refuses the peer.
func TestOwnerAuthenticationWithoutAdmissionGuard(t *testing.T) {
	for _, mode := range []string{"valid", "replacement-replicaset", "foreign-deployment-controller", "replacement-pod"} {
		t.Run(mode, func(t *testing.T) {
			v := ownerFixtureObjects()
			enrollmentReplicaSet := string(v.rs.UID)
			switch mode {
			case "replacement-replicaset":
				v.rs.UID = types.UID(ownerID(99))
				v.pod.OwnerReferences[0].UID = v.rs.UID
			case "foreign-deployment-controller":
				v.rs.OwnerReferences[0].UID = types.UID(ownerID(99))
			case "replacement-pod":
				v.list.Items[0].Endpoints[0].TargetRef.UID = types.UID(ownerID(99))
			}
			now := time.Now().UTC()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || strings.Contains(r.URL.Path, "admissionregistration") || strings.Contains(r.URL.Path, "selfsubject") {
					t.Error("admission guard or probe request", r.Method, r.URL.Path)
					http.NotFound(w, r)
					return
				}
				base, appsBase := "/api/v1/namespaces/"+v.pool.Namespace, "/apis/apps/v1/namespaces/"+v.pool.Namespace
				var obj any
				switch r.URL.Path {
				case base:
					obj = v.ns
				case base + "/services/" + v.pool.Service:
					obj = v.svc
				case base + "/serviceaccounts/" + v.pool.ServiceAccount:
					obj = v.sa
				case appsBase + "/deployments/" + v.pool.Deployment:
					obj = v.deploy
				case appsBase + "/replicasets/" + v.rs.Name:
					obj = v.rs
				case base + "/pods/" + v.pod.Name:
					obj = v.pod
				case "/apis/discovery.k8s.io/v1/namespaces/" + v.pool.Namespace + "/endpointslices":
					obj = v.list
				default:
					t.Error("unexpected path", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				permissionReply(w, obj)
			}))
			defer server.Close()
			control := cfg.NamespaceRef{Name: v.pool.Namespace, UID: v.pool.NamespaceUID}
			config := &rest.Config{Host: server.URL, BearerToken: "synthetic-owner", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
			client, err := NewPermissionClient(config, v.pool.ClusterID, control, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			probe, err := NewPermissionClient(config, v.pool.ClusterID, control, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			guard, err := NewOwnerWorkloadProtection(client, probe, cfg.OwnerWorkloadAdministration{Name: "owner-workload", Deployment: v.pool.Deployment, DeploymentUID: v.pool.DeploymentUID, ControlNamespace: control, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}}, GuardPin{PolicyUID: ownerID(21), PolicyGeneration: 1, BindingUID: ownerID(22), BindingResourceVersion: "20"})
			if err != nil {
				t.Fatal(err)
			}
			endpoints, err := NewOwnerEndpoints(client, v.pool)
			if err != nil {
				t.Fatal(err)
			}
			configuration := value.OwnerConfiguration{Pool: v.pool, Revision: identity.Revision{UID: ownerID(23), Generation: 1, Digest: artifact.Digest{6}}, ProtectionDigest: guard.digest, IssuerRoots: [][]byte{{8}}}
			observation := func() value.OwnerConfigurationObservation {
				at := time.Now().UTC()
				return value.OwnerConfigurationObservation{Configuration: configuration.Clone(), ObservedAt: at, FreshUntil: at.Add(5 * time.Second)}
			}
			certificate := value.OwnerCertificate{Binding: v.binding, Usage: "client", Digest: artifact.Digest{1}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute)}
			claimed := now.Add(-time.Second)
			_, hold, _ := value.OwnerCertificateWindow(claimed)
			enrollment := value.OwnerEnrollment{ID: ownerID(24), Binding: v.binding, Usage: "client", Pool: v.pool, SourceUID: ownerID(23), Pod: v.pod.Name, ReplicaSet: "hub-rs", ReplicaSetUID: enrollmentReplicaSet, PublicKeyDigest: artifact.Digest{2}, InitialTokenDigest: artifact.Digest{3}, InitialWorkloadDigest: artifact.Digest{4}, InitialProtectionDigest: guard.digest, ClaimedAt: claimed, InitialHoldUntil: hold.Add(time.Minute)}
			registry := ownerAuthRegistry(func(context.Context, value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
				at := time.Now().UTC()
				return value.OwnerRegistrationObservation{Enrollment: enrollment, Certificate: certificate, Configuration: observation(), ObservedAt: at, FreshUntil: at.Add(5 * time.Second)}, nil
			})
			configurations := ownerConfigurationFunc(func(context.Context) (value.OwnerConfigurationObservation, error) { return observation(), nil })
			s := app.OwnerAuthenticator{Registry: registry, Routes: &app.OwnerRoutes{Configurations: configurations, Endpoints: endpoints, Now: time.Now}, Protection: guard, Now: time.Now}
			got, err := s.AuthenticateOwner(context.Background(), ownerAuthPeer{certificate})
			if mode != "valid" {
				if err == nil || got != (value.AuthenticatedOwner{}) {
					t.Fatal("wrong Pod chain authenticated", got)
				}
				return
			}
			if err != nil || got.Certificate != certificate || got.Pod != v.pod.Name || got.ProtectionDigest != guard.digest || !got.Valid(time.Now()) {
				t.Fatal("owner authentication without admission guard failed", err, got)
			}
		})
	}
}
