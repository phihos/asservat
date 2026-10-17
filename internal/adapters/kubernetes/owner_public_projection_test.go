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

// ADR-194: the promoted owner starts only when the referenced public runtime
// projection is the immutable product Secret of the mounted manifest and its
// every key equals the mounted file; operator keys in the root are ignored.
func TestOwnerPublicProjectionMatchesMountedRoot(t *testing.T) {
	for _, mode := range []string{"valid", "mutable", "other-uid", "changed-bytes", "other-root", "missing-file", "wrong-reference"} {
		t.Run(mode, func(t *testing.T) {
			x := newOwnerIdentityObjectFixture(t)
			in := x.reader.activation.Input
			ref := contracts.WorkerObjectReference{Name: contracts.PublicRuntimeProjectionName(x.reader.input.InstallationID), UID: ownerID(3600)}
			x.reader.input.Public = &contracts.OwnerPublicDeployment{RuntimeProjection: ref}
			manifest, _ := json.Marshal(contracts.PublicRuntimeCredentialManifest{Format: contracts.PublicRuntimeCredentialManifestFormat, RootUID: ownerID(3601), SetupID: ownerID(3602)})
			data := map[string][]byte{contracts.PublicRuntimeCredentialManifestFile: manifest, "sql-public-identity-read.json": []byte("synthetic-login"), contracts.PublicAuditKeysFile: []byte("synthetic-keys")}
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
				mounted["sql-public-identity-read.json"] = []byte("replaced-login")
			case "other-root":
				secret.Annotations["asservat.io/role-root-uid"] = ownerID(3698)
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
			if mode == "wrong-reference" {
				check.UID = ownerID(3697)
			}
			ctx, end := context.WithTimeout(context.Background(), 5*time.Second)
			defer end()
			err := x.reader.VerifyPublicProjection(ctx, check, mounted)
			if (err == nil) != (mode == "valid") {
				t.Fatal(mode, err)
			}
		})
	}
}
