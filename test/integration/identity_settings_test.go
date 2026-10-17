package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func testIdentitySettings(t *testing.T, ctx context.Context, c *rest.Config, cluster string, control cfg.NamespaceRef, readerToken string) {
	t.Helper()
	admin, err := kubernetes.NewForConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../examples/identity-settings.json")
	if err != nil {
		t.Fatal(err)
	}
	object, err := admin.CoreV1().ConfigMaps(control.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "identity-settings"}, Data: map[string]string{"identity.json": string(data)}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.RbacV1().Roles(control.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "identity-settings-reader"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{object.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.RbacV1().RoleBindings(control.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "identity-settings-reader"}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "permission-reader", Namespace: control.Name}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "identity-settings-reader"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	limited := &rest.Config{Host: c.Host, BearerToken: readerToken, TLSClientConfig: rest.TLSClientConfig{CAData: c.CAData, CAFile: c.CAFile, ServerName: c.ServerName}}
	observed, err := kube.NewPermissionClient(limited, cluster, control, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := kube.NewIdentityPolicyClient(observed, object.Name, string(object.UID), "https://id.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	before, err := reader.IdentityPolicy(ctx, "https://id.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	claims := identity.Claims{Issuer: before.Issuer, Subject: "developer", ClientID: "asservat-console", Groups: []string{"platform-developers"}, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), KeyUntil: now.Add(time.Minute)}
	if _, err = identity.Admit(claims, before, now); err != nil {
		t.Fatal(err)
	}
	limitedAPI, err := kubernetes.NewForConfig(limited)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = limitedAPI.CoreV1().ConfigMaps(control.Name).Patch(ctx, object.Name, types.MergePatchType, []byte(`{"data":{"identity.json":"forged"}}`), meta.PatchOptions{}); !apierrors.IsForbidden(err) {
		t.Fatal("identity reader can edit policy")
	}
	if _, err = limitedAPI.CoreV1().ConfigMaps(control.Name).Get(ctx, "permission-bootstrap", meta.GetOptions{}); !apierrors.IsForbidden(err) {
		t.Fatal("identity reader can read other protected configuration")
	}
	var settings map[string]any
	if json.Unmarshal(data, &settings) != nil {
		t.Fatal("fixture")
	}
	settings["eligibleGroups"] = []string{"another-team"}
	settings["revision"] = 2
	encoded, _ := json.Marshal(settings)
	object.Data["identity.json"] = string(encoded)
	object, err = admin.CoreV1().ConfigMaps(control.Name).Update(ctx, object, meta.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	after, err := reader.IdentityPolicy(ctx, claims.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision.Digest == before.Revision.Digest {
		t.Fatal("changed policy digest retained")
	}
	if _, err = identity.Admit(claims, after, time.Now()); !errors.Is(err, identity.ErrDenied) {
		t.Fatal("removed organization membership accepted")
	}
	if err = admin.CoreV1().ConfigMaps(control.Name).Delete(ctx, object.Name, meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	object.ResourceVersion = ""
	object.UID = ""
	if _, err = admin.CoreV1().ConfigMaps(control.Name).Create(ctx, object, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = reader.IdentityPolicy(ctx, claims.Issuer); err == nil {
		t.Fatal("same-name policy replacement accepted")
	}
	testSubmissionTrustSource(t, ctx, c, cluster, control, readerToken)
}
