package integration

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type installationWitnessLab struct {
	reader   *kube.InstallationWitnessReader
	consumer *kube.InstallationWitnessConsumer
	writer   kubernetes.Interface
	probe    kubernetes.Interface
	scope    value.InstallationWitnessScope
	plan     cfg.ConfigMapAdministration
	fresh    map[string]string
	clients  map[string]*kube.PermissionClient
}

func newInstallationWitnessLab(t *testing.T, ctx context.Context, config *rest.Config, admin kubernetes.Interface, name string) installationWitnessLab {
	t.Helper()
	who, err := admin.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	ns, e := admin.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	scope := value.InstallationWitnessScope{InstallationID: custodyID(), IssuerEpoch: custodyID(), ClusterID: custodyID(), Namespace: name, NamespaceUID: string(ns.UID), Name: "installation", WriterAccount: "bootstrap"}
	clients := map[string]*kube.PermissionClient{}
	apis := map[string]kubernetes.Interface{}
	for _, account := range []string{"reader", "probe", "bootstrap"} {
		sa, e := admin.CoreV1().ServiceAccounts(name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: account}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		if account == scope.WriterAccount {
			scope.WriterAccountUID = string(sa.UID)
		}
		token, e := admin.CoreV1().ServiceAccounts(name).CreateToken(ctx, account, &auth.TokenRequest{}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		c := &rest.Config{Host: config.Host, BearerToken: token.Status.Token, TLSClientConfig: config.TLSClientConfig}
		c.CertData, c.KeyData, c.CertFile, c.KeyFile = nil, nil, "", ""
		clients[account], e = kube.NewPermissionClient(c, scope.ClusterID, cfg.NamespaceRef{Name: name, UID: string(ns.UID)}, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		apis[account], e = kubernetes.NewForConfig(c)
		if e != nil {
			t.Fatal(e)
		}
	}
	fresh, e := kube.FreshInstallationWitnessData(scope.InstallationID, scope.IssuerEpoch, scope.WriterAccountUID)
	if e != nil {
		t.Fatal(e)
	}
	cm, e := admin.CoreV1().ConfigMaps(name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: scope.Name}, Data: fresh}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	scope.UID = string(cm.UID)
	plan := cfg.ConfigMapAdministration{Name: name, SourceName: cm.Name, ControlNamespace: cfg.NamespaceRef{Name: name, UID: scope.NamespaceUID}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}, {Kind: "User", Name: scope.WriterUsername()}}}
	policy, binding, e := kube.InstallationWitnessAdmission(plan)
	if e != nil {
		t.Fatal(e)
	}
	policy, e = admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	binding, e = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	role := &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{name}, Verbs: []string{"get"}}, {APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{name}, Verbs: []string{"get"}}}}
	if _, e = admin.RbacV1().ClusterRoles().Create(ctx, role, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "reader", Namespace: name}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: name}}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	for _, account := range []string{"reader", "probe", "bootstrap"} {
		verbs := []string{"get"}
		if account != "reader" {
			verbs = append(verbs, "update")
		}
		if _, e = admin.RbacV1().Roles(name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: account}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{cm.Name}, Verbs: verbs}}}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		if _, e = admin.RbacV1().RoleBindings(name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: account}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: account, Namespace: name}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: account}}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
	}
	pin := kube.GuardPin{PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion}
	reader, e := kube.NewInstallationWitnessReader(clients["reader"], clients["probe"], plan, pin, scope)
	if e != nil {
		t.Fatal(e)
	}
	consumer, e := kube.NewInstallationWitnessConsumer(reader, clients["bootstrap"])
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, e = reader.ReadInstallationWitness(ctx); e == nil {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("witness protection not ready", e)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return installationWitnessLab{reader, consumer, apis["bootstrap"], apis["probe"], scope, plan, fresh, clients}
}

func TestInstallationWitnessWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run make context-integration")
	}
	var f fixture
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &f) != nil || len(f.Clusters) == 0 {
		t.Fatal("fixture unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	config, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	create := func(t *testing.T, name string) installationWitnessLab {
		return newInstallationWitnessLab(t, ctx, config, admin, name)
	}
	claim := func() value.InitialActivationClaim {
		now := time.Now().UTC().Truncate(time.Microsecond)
		// Intent only: this fixture does not assert that SQL is pristine or
		// audited, and no product activation method is invoked by this port.
		return value.InitialActivationClaim{ID: custodyID(), Database: value.DatabaseIncarnation{StartedAt: now.Add(-time.Minute), DatabaseOID: 16384, SchemaVersion: 31}, FleetSource: identity.Revision{UID: "synthetic-source", Generation: 1, Digest: [32]byte{1}}, PlanDigest: artifact.Digest{2}, NotBefore: now, NotAfter: now.Add(time.Minute)}
	}
	t.Run("consume-retry-native-immutability-and-replacement", func(t *testing.T) {
		s := create(t, "installation-witness")
		c := claim()
		w, e := s.consumer.ConsumeInstallationWitness(ctx, c)
		if e != nil || w.Claim == nil || *w.Claim != c || !w.Valid(time.Now()) {
			t.Fatal("consumption failed", e)
		}
		retry, e := s.consumer.ConsumeInstallationWitness(ctx, c)
		if e != nil || retry.ResourceVersion != w.ResourceVersion || *retry.Claim != c {
			t.Fatal("retry changed consumption", e)
		}
		changed := c
		changed.Database.DatabaseOID++
		if _, e = s.consumer.ConsumeInstallationWitness(ctx, changed); e == nil {
			t.Fatal("changed database reused witness")
		}
		cm, e := s.writer.CoreV1().ConfigMaps(s.scope.Namespace).Get(ctx, s.scope.Name, meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		cm.Data = s.fresh
		if _, e = s.writer.CoreV1().ConfigMaps(s.scope.Namespace).Update(ctx, cm, meta.UpdateOptions{}); !apierrors.IsInvalid(e) {
			t.Fatal("native immutable data could be reset", e)
		}
		if e = s.writer.CoreV1().ConfigMaps(s.scope.Namespace).Delete(ctx, s.scope.Name, meta.DeleteOptions{}); !apierrors.IsForbidden(e) {
			t.Fatal("consumer could delete witness", e)
		}
		if _, e = s.writer.CoreV1().ConfigMaps(s.scope.Namespace).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "replacement"}, Data: s.fresh}, meta.CreateOptions{}); !apierrors.IsForbidden(e) {
			t.Fatal("consumer could create replacement witness", e)
		}
		if e = admin.CoreV1().ConfigMaps(s.scope.Namespace).Delete(ctx, s.scope.Name, meta.DeleteOptions{}); e != nil {
			t.Fatal(e)
		}
		if _, e = s.reader.ReadInstallationWitness(ctx); e == nil {
			t.Fatal("missing witness remained observable")
		}
		if _, e = admin.CoreV1().ConfigMaps(s.scope.Namespace).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: s.scope.Name}, Data: s.fresh}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		if _, e = s.reader.ReadInstallationWitness(ctx); e == nil {
			t.Fatal("recreated name inherited witness identity")
		}
	})
	t.Run("four-way-race-retains-one-exact-consumption", func(t *testing.T) {
		s := create(t, "installation-witness-race")
		claims := []value.InitialActivationClaim{claim(), claim(), claim(), claim()}
		var wg sync.WaitGroup
		for _, c := range claims {
			wg.Add(1)
			go func(c value.InitialActivationClaim) {
				defer wg.Done()
				_, _ = s.consumer.ConsumeInstallationWitness(ctx, c)
			}(c)
		}
		wg.Wait()
		w, e := s.reader.ReadInstallationWitness(ctx)
		if e != nil || w.Claim == nil {
			t.Fatal("race left no durable consumption", e)
		}
		matches := 0
		for _, c := range claims {
			r, e := s.consumer.ConsumeInstallationWitness(ctx, c)
			if c == *w.Claim {
				matches++
				if e != nil || r.ResourceVersion != w.ResourceVersion {
					t.Fatal("winner could not recover exact consumption", e)
				}
			} else if e == nil {
				t.Fatal("loser reused witness")
			}
		}
		if matches != 1 {
			t.Fatal("stored consumption did not match one submitted attempt")
		}
	})
	t.Run("expired-claim-and-missing-protection-do-not-consume", func(t *testing.T) {
		s := create(t, "installation-witness-deny")
		c := claim()
		c.NotBefore, c.NotAfter = c.NotBefore.Add(-time.Minute), c.NotBefore
		c.Database.StartedAt = c.NotBefore.Add(-time.Minute)
		if _, e := s.consumer.ConsumeInstallationWitness(ctx, c); e == nil {
			t.Fatal("expired claim consumed witness")
		}
		if e := admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, s.plan.Name, meta.DeleteOptions{}); e != nil {
			t.Fatal(e)
		}
		if _, e := s.consumer.ConsumeInstallationWitness(ctx, claim()); e == nil {
			t.Fatal("missing protection allowed consumption")
		}
		cm, e := admin.CoreV1().ConfigMaps(s.scope.Namespace).Get(ctx, s.scope.Name, meta.GetOptions{})
		if e != nil || (cm.Immutable != nil && *cm.Immutable) || cm.Data["witness.json"] != s.fresh["witness.json"] {
			t.Fatal("denied operation mutated witness", e)
		}
	})
}
