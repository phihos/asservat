package integration

import (
	"context"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	authn "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// Exercise the actual installed connector Role as that account. This mints no
// capture authority and reads no Secret payload; each operation is only an API
// permission review. The existing input proof checks exact live metadata later.
func qualifyApprovedRecordingInputPermissions(t *testing.T, parent context.Context, admin kubernetes.Interface, kubeconfig, namespace string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	token, err := admin.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, kube.RegionalAccount, &authn.TokenRequest{Spec: authn.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{})
	if err != nil || token.Status.Token == "" {
		t.Fatal("connector permission-review token", err)
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal("connector permission-review configuration", err)
	}
	config = rest.AnonymousClientConfig(config)
	config.BearerToken = token.Status.Token
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal("connector permission-review client", err)
	}
	for _, tc := range []struct {
		namespace, name, verb string
		allowed               bool
	}{
		{namespace, kube.RegionalNodes, "get", true},
		{namespace, kube.RegionalNodes, "update", false},
		{namespace, "unrelated-secret", "get", false},
		{namespace, "", "list", false},
		{namespace, "", "watch", false},
		{"default", kube.RegionalNodes, "get", false},
	} {
		review, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authz.SelfSubjectAccessReview{Spec: authz.SelfSubjectAccessReviewSpec{ResourceAttributes: &authz.ResourceAttributes{Namespace: tc.namespace, Verb: tc.verb, Resource: "secrets", Name: tc.name}}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal("installed connector Secret permission review", tc.verb, tc.namespace, err)
		}
		if review.Status.Allowed != tc.allowed {
			t.Fatal("installed connector Secret permission differs", tc.verb, tc.namespace, tc.name, review.Status.Allowed)
		}
	}
	t.Log("installed connector: exact listener Secret GET allowed; other Secret GET, list/watch/update and other-namespace GET denied")
}
