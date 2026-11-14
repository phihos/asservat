package bootstrap

import (
	"testing"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSecretsCopyCreatesOneImmutableCredential(t *testing.T) {
	api := fake.NewClientset(&core.Secret{ObjectMeta: meta.ObjectMeta{Name: "a-s3-download-read", Namespace: "hub"}, Data: map[string][]byte{contracts.ObjectStoreCredentialFile: []byte(`{"accessKeyID":"AK","secretAccessKey":"SK","sessionToken":""}`), "other": []byte("no")}})
	store := secretStore{api: api.CoreV1().Secrets("hub"), namespace: "hub"}
	c := contracts.SecretsCopy{Source: "a-s3-download-read", Namespace: "a-downloads", Secret: "a-s3-download-read"}
	for range 2 {
		if err := store.copyImmutable(t.Context(), api.CoreV1().Secrets("a-downloads"), c); err != nil {
			t.Fatal(err)
		}
	}
	got, err := api.CoreV1().Secrets("a-downloads").Get(t.Context(), c.Secret, meta.GetOptions{})
	if err != nil || got.Immutable == nil || !*got.Immutable || len(got.Data) != 1 || string(got.Data[contracts.ObjectStoreCredentialFile]) != `{"accessKeyID":"AK","secretAccessKey":"SK"}` {
		t.Fatal("copy", got, err)
	}
	missing := contracts.SecretsCopy{Source: "absent", Namespace: "a-downloads", Secret: "other"}
	if err := store.copyImmutable(t.Context(), api.CoreV1().Secrets("a-downloads"), missing); err == nil {
		t.Fatal("missing source copied")
	}
}
