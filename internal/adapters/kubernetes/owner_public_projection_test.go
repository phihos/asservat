package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

// ADR-194: the promoted owner starts only when the named public runtime
// projection Secret's every key equals the mounted file; operator keys in the
// root are ignored. It is matched by name and content: a Helm-rendered Secret
// without installer UIDs, annotations or immutability is accepted.
func TestOwnerPublicProjectionMatchesMountedRoot(t *testing.T) {
	accepted := map[string]bool{"valid": true, "mutable": true, "other-uid": true, "no-annotations": true, "other-reference-uid": true}
	for _, mode := range []string{"valid", "mutable", "other-uid", "no-annotations", "other-reference-uid", "changed-bytes", "missing-file", "bad-manifest", "other-name", "not-opaque"} {
		t.Run(mode, func(t *testing.T) {
			x := newOwnerIdentityObjectFixture(t)
			in := x.reader.activation.Input
			ref := contracts.WorkerObjectReference{Name: contracts.PublicRuntimeProjectionName(x.reader.input.InstallationID), UID: ownerID(3600)}
			x.reader.input.Public = &contracts.OwnerPublicDeployment{RuntimeProjection: ref}
			manifest, _ := json.Marshal(contracts.PublicRuntimeCredentialManifest{Format: contracts.PublicRuntimeCredentialManifestFormat, RootUID: ownerID(3601), SetupID: ownerID(3602)})
			data := map[string][]byte{contracts.PublicRuntimeCredentialManifestFile: manifest, "sql-public-hub-runtime.json": []byte("synthetic-login"), contracts.PublicAuditKeysFile: []byte("synthetic-keys")}
			secret := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: ref.Name, Namespace: in.Namespace.Name, UID: types.UID(ref.UID), ResourceVersion: "7",
				Annotations: map[string]string{"asservat.io/role-root-uid": ownerID(3601), "asservat.io/role-setup-id": ownerID(3602), "asservat.io/projection-id": ownerID(3603)}}, Immutable: ptr.To(true), Type: core.SecretTypeOpaque, Data: data}
			mounted := map[string][]byte{"client-secret": []byte("operator-only")}
			for k, v := range data {
				mounted[k] = append([]byte(nil), v...)
			}
			switch mode {
			case "mutable":
				secret.Immutable = nil
			case "other-uid":
				secret.UID = types.UID(ownerID(3699))
			case "changed-bytes":
				mounted["sql-public-hub-runtime.json"] = []byte("replaced-login")
			case "no-annotations":
				secret.Annotations = nil
			case "bad-manifest":
				mounted[contracts.PublicRuntimeCredentialManifestFile] = []byte("{")
			case "not-opaque":
				secret.Type = core.SecretTypeTLS
			case "missing-file":
				delete(mounted, contracts.PublicAuditKeysFile)
			}
			x.extra = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/"+in.Namespace.Name+"/secrets/"+ref.Name {
					return false
				}
				permissionReply(w, secret)
				return true
			}
			check := ref
			switch mode {
			case "other-reference-uid":
				check.UID = ownerID(3697)
			case "other-name":
				check.Name = "other-projection"
			}
			ctx, end := context.WithTimeout(context.Background(), 5*time.Second)
			defer end()
			err := x.reader.VerifyPublicProjection(ctx, check, mounted)
			if (err == nil) != accepted[mode] {
				t.Fatal(mode, err)
			}
		})
	}
}
