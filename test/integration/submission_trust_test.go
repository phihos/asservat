package integration

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
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

func testSubmissionTrustSource(t *testing.T, ctx context.Context, c *rest.Config, cluster string, control cfg.NamespaceRef, token string) {
	t.Helper()
	admin, e := kubernetes.NewForConfig(c)
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile("../../examples/submission-trust.json")
	if e != nil {
		t.Fatal(e)
	}
	var settings contracts.SubmissionTrust
	if json.Unmarshal(data, &settings) != nil {
		t.Fatal("fixture")
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	settings.Keys[0].PublicKey = base64.StdEncoding.EncodeToString(pub)
	settings.Keys[0].NotBefore = now.Add(-time.Minute)
	settings.Keys[0].NotAfter = now.Add(time.Hour)
	data, e = json.Marshal(settings)
	if e != nil {
		t.Fatal(e)
	}
	object, e := admin.CoreV1().ConfigMaps(control.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "submission-trust"}, Data: map[string]string{"submission.json": string(data)}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	limited := &rest.Config{Host: c.Host, BearerToken: token, TLSClientConfig: rest.TLSClientConfig{CAData: c.CAData, CAFile: c.CAFile, ServerName: c.ServerName}}
	client, e := kube.NewPermissionClient(limited, cluster, control, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	reader, e := kube.NewSubmissionTrustClient(client, object.Name, string(object.UID), settings.RootID, settings.InstallationID, settings.IssuerEpoch)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := reader.SubmissionTrust(ctx); e == nil {
		t.Fatal("signing trust readable without explicit RBAC")
	}
	_, e = admin.RbacV1().Roles(control.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "submission-trust-reader"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{object.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	_, e = admin.RbacV1().RoleBindings(control.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "submission-trust-reader"}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "permission-reader", Namespace: control.Name}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "submission-trust-reader"}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	limitedAPI, e := kubernetes.NewForConfig(limited)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := limitedAPI.CoreV1().ConfigMaps(control.Name).Patch(ctx, object.Name, types.MergePatchType, []byte(`{"data":{"submission.json":"forged"}}`), meta.PatchOptions{}); !apierrors.IsForbidden(e) {
		t.Fatal("reader changed signing trust")
	}
	protocol, e := jose.NewPolicySubmissions(settings.RootID, settings.InstallationID, settings.IssuerEpoch, settings.Keys[0].ID, reader, func(context.Context) crypto.Signer { return key }, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	intent := value.PolicySubmissionIntent{RootID: settings.RootID, InstallationID: settings.InstallationID, IssuerEpoch: settings.IssuerEpoch, Nonce: custodyID(), Actor: identity.Principal{Issuer: "https://id.invalid", Subject: "synthetic-human", ClientID: "console", Kind: identity.Human}, Source: identity.Revision{UID: "synthetic-policy", Generation: 1, Digest: artifact.Digest{1}}, ClusterID: cluster, NamespaceUID: "synthetic-namespace", Name: "synthetic-policy", ScopeDigest: artifact.Digest{2}, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second)}
	signed, e := protocol.SignPolicySubmission(ctx, intent)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := protocol.VerifyPolicySubmission(ctx, signed, intent); e != nil {
		t.Fatal(e)
	}
	settings.Revision++
	settings.Keys[0].ID = "replacement-key"
	data, e = json.Marshal(settings)
	if e != nil {
		t.Fatal(e)
	}
	object.Data["submission.json"] = string(data)
	object, e = admin.CoreV1().ConfigMaps(control.Name).Update(ctx, object, meta.UpdateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := protocol.VerifyPolicySubmission(ctx, signed, intent); e == nil {
		t.Fatal("removed Kubernetes signing key remained accepted")
	}
	if e := admin.CoreV1().ConfigMaps(control.Name).Delete(ctx, object.Name, meta.DeleteOptions{}); e != nil {
		t.Fatal(e)
	}
	object.ResourceVersion = ""
	object.UID = ""
	if _, e := admin.CoreV1().ConfigMaps(control.Name).Create(ctx, object, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e := reader.SubmissionTrust(ctx); e == nil {
		t.Fatal("same-name signing trust replacement accepted")
	}
	t.Log("real Kubernetes signing trust: named read-only RBAC, current JWS validation, removed-key and ConfigMap-replacement rejection passed")
}
