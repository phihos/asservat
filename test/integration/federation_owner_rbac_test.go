package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Native controller objects, the exact rendered federation RBAC and independent
// workload-admission denial are real. SQL registration/configuration and the
// certificate presentation are explicit fixture facts, like the hub's delegated
// presented-certificate port; this does not qualify TLS, enrollment or Open.
func TestFederationOwnerReadsWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("owned context fixture required")
	}
	raw, err := os.ReadFile(path)
	var f fixture
	if err != nil || json.Unmarshal(raw, &f) != nil || len(f.Clusters) == 0 {
		t.Fatal("fixture unavailable")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	x := newOwnerObservationNativeCostFixture(t, ctx, f)
	admin, err := kubernetes.NewForConfig(x.config)
	if err != nil {
		t.Fatal(err)
	}
	p := x.pool
	ns := contracts.WorkerObjectReference{Name: p.Namespace, UID: p.NamespaceUID}
	account, err := admin.CoreV1().ServiceAccounts(p.Namespace).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: contracts.FederationServiceAccountName(p.InstallationID)}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	d := contracts.FederationDeployment{Format: contracts.FederationDeploymentFormat, InstallationID: p.InstallationID, ClusterID: p.ClusterID, Port: contracts.FederationPort,
		Owner:                  &contracts.OwnerGuardInputs{Namespace: ns, WorkloadGuard: contracts.OwnerDeploymentGuard{Name: x.plan.Name}},
		ProviderAuthentication: &contracts.FederationProviderAuthentication{Namespace: ns, ServiceAccount: contracts.WorkerObjectReference{Name: account.Name, UID: string(account.UID)}}}
	w, err := kube.BuildFederationWorkload(p.Namespace, x.pod.Spec.Containers[0].Image, p.Deployment, p.ServiceAccount, d, "NodePort", 0)
	if err != nil {
		t.Fatal(err)
	}
	role, err := admin.RbacV1().Roles(p.Namespace).Create(ctx, w.Role.DeepCopy(), meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.RbacV1().RoleBindings(p.Namespace).Create(ctx, w.Binding.DeepCopy(), meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.RbacV1().ClusterRoles().Create(ctx, w.ClusterRole.DeepCopy(), meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		for _, e := range []error{admin.RbacV1().ClusterRoleBindings().Delete(cleanup, w.ClusterBinding.Name, meta.DeleteOptions{}), admin.RbacV1().ClusterRoles().Delete(cleanup, w.ClusterRole.Name, meta.DeleteOptions{})} {
			if e != nil && !apierrors.IsNotFound(e) {
				t.Error("owned federation RBAC cleanup", e)
			}
		}
	})
	if _, err = admin.RbacV1().ClusterRoleBindings().Create(ctx, w.ClusterBinding.DeepCopy(), meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	token, err := admin.CoreV1().ServiceAccounts(p.Namespace).CreateToken(ctx, account.Name, &auth.TokenRequest{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var accountForbidden atomic.Int64
	scoped := &rest.Config{Host: x.config.Host, BearerToken: token.Status.Token, TLSClientConfig: rest.TLSClientConfig{CAData: x.config.CAData, CAFile: x.config.CAFile}}
	scoped.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return ownerProbeRoundTripper(func(r *http.Request) (*http.Response, error) {
			response, e := next.RoundTrip(r)
			if e == nil && response.StatusCode == http.StatusForbidden && r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/"+p.Namespace+"/serviceaccounts/"+p.ServiceAccount {
				accountForbidden.Add(1)
			}
			return response, e
		})
	}
	api, err := kubernetes.NewForConfig(scoped)
	if err != nil {
		t.Fatal(err)
	}
	newClient := func() *kube.PermissionClient {
		c, e := kube.NewPermissionClient(scoped, p.ClusterID, x.plan.ControlNamespace, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	observer, probe := newClient(), newClient()
	endpoints, err := kube.NewOwnerEndpoints(observer, p)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := kube.NewOwnerWorkloadProtection(observer, probe, x.plan, x.guardPin)
	if err != nil {
		t.Fatal(err)
	}
	binding := value.OwnerBinding{InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PodUID: string(x.pod.UID), ProcessEpoch: custodyID()}
	ca, _ := connectorSQLCA(t)
	configuration := value.OwnerConfiguration{Pool: p, Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: x.pin.ProtectionDigest, IssuerRoots: [][]byte{ca.Raw}}
	// RBAC informer convergence is fixture setup, outside each original product
	// call. Product OwnerEndpoint/AuthenticateOwner are called once per assertion.
	waitAccount := func(allowed bool) {
		wait, end := context.WithTimeout(ctx, 5*time.Second)
		defer end()
		for {
			_, e := api.CoreV1().ServiceAccounts(p.Namespace).Get(wait, p.ServiceAccount, meta.GetOptions{})
			if allowed && e == nil || !allowed && apierrors.IsForbidden(e) {
				return
			}
			if e != nil && !apierrors.IsForbidden(e) {
				t.Fatal("unexpected account RBAC setup error", e)
			}
			select {
			case <-wait.Done():
				t.Fatal("exact account RBAC did not converge")
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	authenticate := func(t *testing.T, want bool) {
		t.Helper()
		call, end := context.WithTimeout(ctx, 5*time.Second)
		defer end()
		now := time.Now().UTC()
		_, hold, e := value.OwnerCertificateWindow(now)
		if e != nil {
			t.Fatal(e)
		}
		certificate := value.OwnerCertificate{Binding: binding, Usage: "server", Digest: artifact.Digest{2}, NotBefore: now.Add(-time.Second), NotAfter: now.Add(time.Minute)}
		facts := &federationOwnerRBACFacts{configuration: value.OwnerConfigurationObservation{Configuration: configuration, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, registration: value.OwnerRegistrationObservation{Certificate: certificate, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Enrollment: value.OwnerEnrollment{ID: custodyID(), Binding: binding, Usage: "server", Pool: p, SourceUID: configuration.Revision.UID, Pod: x.pod.Name, ReplicaSet: x.pod.OwnerReferences[0].Name, ReplicaSetUID: x.replica, PublicKeyDigest: artifact.Digest{3}, InitialTokenDigest: artifact.Digest{4}, InitialWorkloadDigest: artifact.Digest{5}, InitialProtectionDigest: x.pin.ProtectionDigest, ClaimedAt: now, InitialHoldUntil: hold.Add(value.OwnerRegistrationGrace)}}}
		facts.registration.Configuration = facts.configuration
		if !facts.registration.Valid(now) {
			t.Fatal("synthetic registration malformed")
		}
		routes := &app.OwnerRoutes{Configurations: facts, Endpoints: endpoints, Now: time.Now}
		owners := &app.OwnerAuthenticator{Registry: facts, Routes: routes, Protection: guard, Now: time.Now}
		deniedBefore := accountForbidden.Load()
		got, e := owners.AuthenticateOwner(call, facts)
		if (e == nil) != want {
			t.Fatalf("concrete owner authentication allowed=%v: %v", want, e)
		}
		if !want && accountForbidden.Load() != deniedBefore+1 {
			t.Fatal("authentication failed before the intended account GET refusal")
		}
		if want && (!got.Valid(time.Now()) || got.Certificate != certificate || got.Pool != p || facts.registryReads != 2 || facts.configurationReads != 2 || facts.verifications != 2) {
			t.Fatal("full current owner bracket did not complete")
		}
	}
	t.Run("rendered-grants", func(t *testing.T) {
		waitAccount(true)
		if got, e := endpoints.OwnerEndpoint(ctx, binding); e != nil || !got.Valid(time.Now()) || got.Binding != binding {
			t.Fatal("rendered federation endpoint unavailable", e)
		}
		authenticate(t, true)
	})
	if t.Failed() {
		return
	}
	t.Run("unrelated-accounts-and-tokens-denied", func(t *testing.T) {
		if _, e := api.CoreV1().ServiceAccounts(p.Namespace).Get(ctx, "observer", meta.GetOptions{}); !apierrors.IsForbidden(e) {
			t.Fatal("unrelated account GET was not forbidden", e)
		}
		if _, e := api.CoreV1().ServiceAccounts(p.Namespace).List(ctx, meta.ListOptions{}); !apierrors.IsForbidden(e) {
			t.Fatal("account LIST was not forbidden", e)
		}
		if _, e := api.CoreV1().ServiceAccounts(p.Namespace).CreateToken(ctx, p.ServiceAccount, &auth.TokenRequest{}, meta.CreateOptions{}); !apierrors.IsForbidden(e) {
			t.Fatal("owner token creation was not forbidden", e)
		}
		if _, e := api.CoreV1().Secrets(p.Namespace).List(ctx, meta.ListOptions{}); !apierrors.IsForbidden(e) {
			t.Fatal("credential read was not forbidden", e)
		}
	})
	t.Run("removed-grant-real-403", func(t *testing.T) {
		role.Rules = slices.DeleteFunc(role.Rules, func(r rbac.PolicyRule) bool { return slices.Contains(r.Resources, "serviceaccounts") })
		role, err = admin.RbacV1().Roles(p.Namespace).Update(ctx, role, meta.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		waitAccount(false)
		deniedBefore := accountForbidden.Load()
		if _, e := endpoints.OwnerEndpoint(ctx, binding); e == nil {
			t.Fatal("endpoint survived missing required native read")
		}
		if accountForbidden.Load() != deniedBefore+1 {
			t.Fatal("endpoint failed before the intended account GET refusal")
		}
		authenticate(t, false)
	})
	t.Run("restored-rendered-grant", func(t *testing.T) {
		role.Rules = w.Role.DeepCopy().Rules
		if _, err = admin.RbacV1().Roles(p.Namespace).Update(ctx, role, meta.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		waitAccount(true)
		authenticate(t, true)
	})
}

// Explicit synthetic accepted SQL and certificate presentation only. Native
// namespace, account, Deployment/Pod/ReplicaSet/EndpointSlice and both guard
// proofs are supplied by the production adapters using the rendered identity.
type federationOwnerRBACFacts struct {
	configuration                                    value.OwnerConfigurationObservation
	registration                                     value.OwnerRegistrationObservation
	registryReads, configurationReads, verifications int
}

func (f *federationOwnerRBACFacts) ReadOwnerConfiguration(context.Context) (value.OwnerConfigurationObservation, error) {
	f.configurationReads++
	return f.configuration, nil
}
func (f *federationOwnerRBACFacts) ReadOwnerRegistration(_ context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	f.registryReads++
	if c != f.registration.Certificate {
		return value.OwnerRegistrationObservation{}, value.ErrDenied
	}
	return f.registration, nil
}
func (f *federationOwnerRBACFacts) OwnerCertificate() (value.OwnerCertificate, error) {
	return f.registration.Certificate, nil
}
func (f *federationOwnerRBACFacts) VerifyCurrentOwner(c value.OwnerConfigurationObservation) (value.OwnerCertificate, error) {
	f.verifications++
	if !c.Configuration.Equal(f.configuration.Configuration) {
		return value.OwnerCertificate{}, value.ErrDenied
	}
	return f.registration.Certificate, nil
}
