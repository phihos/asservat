package integration

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// This exercises the product policy against the owned native apiserver. The
// fixture creates only public probe prerequisites and synthetic Secret bytes;
// it does not create a private bootstrap seed, issue SQL/provider credentials,
// launch a workload, or establish installation/recovery authority.
func TestInitialBootstrapGuardWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run owned context-integration fixture")
	}
	var f fixture
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &f) != nil || len(f.Clusters) == 0 {
		t.Fatal("context fixture unavailable")
	}
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	kc, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal("owned API configuration unavailable")
	}
	api, err := kubernetes.NewForConfig(kc)
	if err != nil {
		t.Fatal("owned API client unavailable")
	}
	who, err := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("fixture administrator identity unavailable")
	}
	namespace := "bootstrap-guard-" + custodyID()[:8]
	desired := initialBootstrapGuardDesired(t, kc, namespace, who.Status.UserInfo.Username)
	policy, binding, err := kube.InitialBootstrapAdmission(desired)
	if err != nil {
		t.Fatal("actual bootstrap policy builder rejected public fixture", err)
	}
	var ns *core.Namespace
	var policies []*admission.ValidatingAdmissionPolicy
	var installedBinding *admission.ValidatingAdmissionPolicyBinding
	t.Cleanup(func() {
		clean, end := context.WithTimeout(context.Background(), 30*time.Second)
		defer end()
		if installedBinding != nil {
			e := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(clean, installedBinding.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &installedBinding.UID}})
			if e != nil && !apierrors.IsNotFound(e) {
				t.Error("owned bootstrap binding cleanup", e)
			}
		}
		for _, p := range policies {
			if e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(clean, p.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &p.UID}}); e != nil && !apierrors.IsNotFound(e) {
				t.Error("owned bootstrap policy cleanup", e)
			}
		}
		if ns == nil {
			return
		}
		for {
			e := api.CoreV1().Namespaces().Delete(clean, ns.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &ns.UID}})
			if e == nil || apierrors.IsNotFound(e) {
				break
			}
			// Admission cache convergence after removing this exact binding is
			// the only retryable cleanup failure; keep the original UID/deadline.
			if !initialBootstrapGuardDenial(e, policy.Name) || clean.Err() != nil {
				t.Error("owned bootstrap namespace deletion", e)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		for clean.Err() == nil {
			_, e := api.CoreV1().Namespaces().Get(clean, ns.Name, meta.GetOptions{})
			if apierrors.IsNotFound(e) {
				return
			}
			if e != nil {
				t.Error("owned bootstrap namespace cleanup observation", e)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Error("owned bootstrap namespace did not terminate normally")
	})

	// Reproduce the previously generated match condition exactly, retaining
	// the rest of the product policy. Kubernetes v0.37.0 documents variables
	// as unavailable here, before the policy's variable composition phase.
	if !t.Run("original-match-condition-rejected", func(t *testing.T) {
		old := policy.DeepCopy()
		old.Name += "-old"
		old.Spec.MatchConditions[0].Expression = strings.NewReplacer(
			"(has(request.resource.group) ? request.resource.group : '')", "variables.group",
			"(has(request.namespace) ? request.namespace : '')", "variables.namespace",
			"(has(request.name) ? request.name : '')", "variables.name",
		).Replace(old.Spec.MatchConditions[0].Expression)
		if !strings.Contains(old.Spec.MatchConditions[0].Expression, "variables.group") {
			t.Fatal("fixture no longer reproduces original condition")
		}
		got, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, old, meta.CreateOptions{})
		if e == nil {
			policies = append(policies, got) // Never bind the invalid policy.
			got = initialBootstrapGuardTypecheck(t, ctx, api, got)
			for _, warning := range got.Status.TypeChecking.ExpressionWarnings {
				if strings.Contains(warning.FieldRef, "matchConditions") && strings.Contains(warning.Warning, "variables") {
					t.Log("actual API accepted the object with the original match-condition type error")
					return
				}
			}
			t.Fatal("native API did not reject or diagnose unavailable match-condition variables")
		}
		var status apierrors.APIStatus
		if !apierrors.IsInvalid(e) || !errors.As(e, &status) || status.Status().Details == nil {
			t.Fatal("original policy failed outside native match-condition validation", e)
		}
		for _, cause := range status.Status().Details.Causes {
			if strings.Contains(cause.Field, "matchConditions") && strings.Contains(cause.Message, "variables") {
				t.Log("actual API rejected original match-condition variables")
				return
			}
		}
		t.Fatal("native policy rejection did not identify unavailable match-condition variables")
	}) {
		return
	}

	createdNamespace, err := api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: namespace, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("owned bootstrap namespace unavailable", err)
	}
	ns = createdNamespace
	account := desired.Name + "-probe"
	marker, continuity := desired.Name+"-bootstrap-probe", desired.Name+"-continuity-probe"
	_, err = api.CoreV1().ServiceAccounts(namespace).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: account}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	role, err := api.RbacV1().Roles(namespace).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: account}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{marker, continuity}, Verbs: []string{"get", "update"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.RbacV1().RoleBindings(namespace).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: account}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: account}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: namespace, Name: account}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	markers := map[string]*core.ConfigMap{}
	for _, name := range []string{marker, continuity} {
		markers[name], err = api.CoreV1().ConfigMaps(namespace).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: name}, Data: map[string]string{"public": "synthetic probe marker"}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	anchor, err := api.CoreV1().Secrets(namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: desired.Name + "-probe-lifetime"}, Immutable: ptr.To(true)}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("public observation anchor unavailable", err)
	}
	created, err := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{})
	if err != nil {
		t.Fatal("corrected product policy rejected", err)
	}
	policies = append(policies, created)
	created = initialBootstrapGuardTypecheck(t, ctx, api, created)
	if len(created.Status.TypeChecking.ExpressionWarnings) != 0 {
		t.Fatalf("corrected native policy has type warnings: %v", created.Status.TypeChecking.ExpressionWarnings)
	}
	createdBinding, err := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	installedBinding = createdBinding
	// Wait with a non-persisting exact protected UPDATE, never by attempting
	// destructive deletion before enforcement has propagated.
	until := time.Now().Add(15 * time.Second)
	for {
		copy := markers[marker].DeepCopy()
		copy.Data["proof"] = "synthetic denied mutation"
		_, e := api.CoreV1().ConfigMaps(namespace).Update(ctx, copy, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
		if initialBootstrapGuardDenial(e, policy.Name) {
			break
		}
		if e != nil || !time.Now().Before(until) || ctx.Err() != nil {
			t.Fatal("exact native bootstrap denial did not become available", e)
		}
		time.Sleep(50 * time.Millisecond)
	}
	deny := func(t *testing.T, e error) {
		t.Helper()
		if !initialBootstrapGuardDenial(e, policy.Name) {
			t.Fatal("request did not reach the exact bootstrap guard denial", e)
		}
	}

	t.Run("administrator-private-create-and-cas-only", func(t *testing.T) {
		secret, e := api.CoreV1().Secrets(namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: desired.Name + "-private-progress"}, Data: map[string][]byte{"synthetic": []byte("test-only")}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("original administrator private CREATE denied", e)
		}
		secret.Data["synthetic"] = []byte("test-only-next")
		secret, e = api.CoreV1().Secrets(namespace).Update(ctx, secret, meta.UpdateOptions{})
		if e != nil {
			t.Fatal("original administrator private UPDATE denied", e)
		}
		deny(t, api.CoreV1().Secrets(namespace).Delete(ctx, secret.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &secret.UID}}))
	})
	t.Run("administrator-cannot-delete-namespace", func(t *testing.T) {
		deny(t, api.CoreV1().Namespaces().Delete(ctx, namespace, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &ns.UID}}))
	})
	t.Run("administrator-cannot-change-probe-rbac", func(t *testing.T) {
		changed := role.DeepCopy()
		changed.Rules[0].Verbs = append(changed.Rules[0].Verbs, "delete")
		_, e := api.RbacV1().Roles(namespace).Update(ctx, changed, meta.UpdateOptions{})
		deny(t, e)
	})
	t.Run("unrelated-names-remain-unaffected", func(t *testing.T) {
		cm, e := api.CoreV1().ConfigMaps(namespace).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "unrelated"}, Data: map[string]string{"synthetic": "fixture"}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		cm.Data["synthetic"] = "changed"
		cm, e = api.CoreV1().ConfigMaps(namespace).Update(ctx, cm, meta.UpdateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		if e = api.CoreV1().ConfigMaps(namespace).Delete(ctx, cm.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &cm.UID}}); e != nil {
			t.Fatal(e)
		}
	})

	request := &auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: []string{desired.ProbeAudience}, ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: anchor.Name, UID: anchor.UID}}}
	token, err := api.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, account, request, meta.CreateOptions{})
	if err != nil || token.Status.Token == "" {
		t.Fatal("exact observation-only TokenRequest unavailable")
	}
	// Use only the actual issued observer token and the API root; no admin
	// certificate, impersonation, exec plugin or credential wrapper survives.
	probeConfig := &rest.Config{Host: kc.Host, BearerToken: token.Status.Token, TLSClientConfig: rest.TLSClientConfig{CAData: kc.CAData, CAFile: kc.CAFile, ServerName: kc.ServerName}}
	probe, err := kubernetes.NewForConfig(probeConfig)
	if err != nil {
		t.Fatal("observer client unavailable")
	}
	observed, err := probe.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil || observed.Status.UserInfo.Username != "system:serviceaccount:"+namespace+":"+account {
		t.Fatal("actual observation-only identity differs")
	}
	t.Run("observer-dry-run-only-continuity-exception", func(t *testing.T) {
		copy := markers[continuity].DeepCopy()
		copy.Data["proof"] = "synthetic non-persisting mutation"
		if _, e := probe.CoreV1().ConfigMaps(namespace).Update(ctx, copy, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); e != nil {
			t.Fatal("exact independent continuity dry-run blocked", e)
		}
		_, e := probe.CoreV1().ConfigMaps(namespace).Update(ctx, copy, meta.UpdateOptions{})
		deny(t, e)
		got, e := api.CoreV1().ConfigMaps(namespace).Get(ctx, continuity, meta.GetOptions{})
		if e != nil || got.ResourceVersion != markers[continuity].ResourceVersion || got.Data["proof"] != "" {
			t.Fatal("observation exception persisted a mutation")
		}
	})
	t.Run("observer-bootstrap-probe-still-denied", func(t *testing.T) {
		copy := markers[marker].DeepCopy()
		copy.Data["proof"] = "synthetic denied mutation"
		_, e := probe.CoreV1().ConfigMaps(namespace).Update(ctx, copy, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
		deny(t, e)
	})
	for _, mode := range []string{"audience", "lifetime", "anchor-name"} {
		t.Run("reject-token-"+mode, func(t *testing.T) {
			wrong := request.DeepCopy()
			switch mode {
			case "audience":
				wrong.Spec.Audiences = []string{"unrelated-audience"}
			case "lifetime":
				wrong.Spec.ExpirationSeconds = ptr.To(int64(601))
			case "anchor-name":
				wrong.Spec.BoundObjectRef.Name = "unrelated-anchor"
			}
			_, e := api.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, account, wrong, meta.CreateOptions{})
			deny(t, e)
		})
	}
}

func initialBootstrapGuardTypecheck(t *testing.T, ctx context.Context, api kubernetes.Interface, p *admission.ValidatingAdmissionPolicy) *admission.ValidatingAdmissionPolicy {
	t.Helper()
	until := time.Now().Add(15 * time.Second)
	for p.Status.ObservedGeneration != p.Generation || p.Status.TypeChecking == nil {
		if ctx.Err() != nil || !time.Now().Before(until) {
			t.Fatal("native policy type-check observation unavailable")
		}
		time.Sleep(50 * time.Millisecond)
		got, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, p.Name, meta.GetOptions{})
		if e != nil || got.UID != p.UID || got.Generation != p.Generation {
			t.Fatal("native policy identity changed during type checking")
		}
		p = got
	}
	return p
}

func initialBootstrapGuardDenial(err error, policy string) bool {
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		return false
	}
	s := status.Status()
	if !(s.Code == 422 && s.Reason == meta.StatusReasonInvalid || s.Code == 403 && s.Reason == meta.StatusReasonForbidden) || s.Details == nil {
		return false
	}
	want := "ValidatingAdmissionPolicy '" + policy + "' with binding '" + policy + "' denied request: Asservat trusted bootstrap identities must remain occupied; observation probes cannot mutate them."
	for _, cause := range s.Details.Causes {
		if cause.Message == want {
			return true
		}
	}
	return false
}

func initialBootstrapGuardDesired(t *testing.T, kc *rest.Config, namespace, administrator string) contracts.InitialBootstrap {
	t.Helper()
	ca := kc.CAData
	if len(ca) == 0 && kc.CAFile != "" {
		var e error
		ca, e = os.ReadFile(kc.CAFile)
		if e != nil {
			t.Fatal("owned API roots unavailable")
		}
	}
	var roots [][]byte
	for len(ca) != 0 {
		block, rest := pem.Decode(ca)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatal("owned API root encoding unavailable")
		}
		roots = append(roots, block.Bytes)
		ca = rest
	}
	if len(roots) == 0 {
		t.Fatal("owned API roots missing")
	}
	// The non-Kubernetes origins are structurally valid public placeholders;
	// this guard-only fixture never connects to a provider or issues material.
	return contracts.InitialBootstrap{
		Format: contracts.InitialBootstrapFormat, Name: "install", BootstrapNamespace: namespace, TargetNamespace: namespace + "-target",
		Image: "example.invalid/asservat@sha256:" + strings.Repeat("a", 64), ProbeAudience: "https://kubernetes.default.svc.cluster.local",
		Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: administrator}},
		Kubernetes:     contracts.OwnerProviderEndpoint{Endpoint: kc.Host, Roots: roots},
		Postgres:       contracts.OwnerPostgresEndpoint{Host: "sql.example.test", Port: 5432, Database: "asservat", MaxConnections: 2, Roots: roots},
		AuditStore:     contracts.OwnerAuditStore{Endpoint: "https://audit.example.test", Region: "test", Bucket: "audit", Roots: roots},
		KeyService:     contracts.ConfigurationKeyService{Endpoint: "https://keys.example.test", AuditMount: "transit", AuditKey: "audit", Roots: roots},
		Fleet:          contracts.InitialBootstrapFleet{Issuer: "https://identity.example.test", Clients: []string{"asservat-console"}, Subjects: []contracts.IdentitySubject{}, Groups: []string{"platform-operators"}, DeliveryProfiles: []string{"cluster-enrollment"}, MaxActiveBootstraps: 8, MaxBootstrapHistory: 1024, MaxClusters: 32},
		Providers:      contracts.InitialBootstrapProviders{IssuerPolicy: "issuer", WrapRole: "wrap-role", WrapPolicy: "wrap-policy", UnwrapRole: "unwrap-role", UnwrapPolicy: "unwrap-policy"},
	}
}
