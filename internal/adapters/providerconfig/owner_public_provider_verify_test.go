package providerconfig

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// ADR-194 step 6: the readback returns the signing key's latest version and
// public key and the worker issuer, and refuses wrong key types, exportable
// keys and changed roles.
func TestOwnerPublicReadbackChecksKeyTypes(t *testing.T) {
	for _, mode := range []string{"valid", "exportable-signing", "session-not-aes", "short-public-key", "changed-worker-role", "changed-public-policy"} {
		t.Run(mode, func(t *testing.T) {
			f := newSetupFixture(t)
			in := f.in
			in.Public = &contracts.OwnerPublicDeployment{SessionTransit: contracts.OwnerPublicTransit{Mount: "public-transit", Key: "sessions"}, WorkSigning: contracts.OwnerPublicSigning{Mount: "public-transit", Name: "work"},
				WorkerPKI: contracts.OwnerPublicWorkerPKI{Mount: "worker-pki", Role: "worker", IssuerEpoch: "10000000-0000-4000-8000-000000001497"}}
			public := bytes.Repeat([]byte{7}, 32)
			signing := map[string]any{"name": "work", "type": "ed25519", "derived": false, "exportable": false, "allow_plaintext_backup": false, "deletion_allowed": false, "supports_signing": true, "latest_version": 2,
				"keys": map[string]any{"1": map[string]any{"public_key": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))}, "2": map[string]any{"public_key": base64.StdEncoding.EncodeToString(public)}}}
			session := map[string]any{"name": "sessions", "type": "aes256-gcm96", "derived": false, "exportable": false, "allow_plaintext_backup": false, "deletion_allowed": false, "supports_encryption": true, "supports_decryption": true, "latest_version": 1, "min_decryption_version": 1, "min_encryption_version": 0}
			role, err := ownerWorkerPKIRole(in.InstallationID)
			if err != nil {
				t.Fatal(err)
			}
			roles, _, err := OwnerPublicProviderRecipeFor(in, f.profile, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "exportable-signing":
				signing["exportable"] = true
			case "session-not-aes":
				session["type"] = "chacha20-poly1305"
			case "short-public-key":
				signing["keys"].(map[string]any)["2"] = map[string]any{"public_key": base64.StdEncoding.EncodeToString(public[:16])}
			case "changed-worker-role":
				role = json.RawMessage(bytes.Replace(role, []byte(`"client_flag":true`), []byte(`"client_flag":false`), 1))
			case "changed-public-policy":
				roles[0].Policy = json.RawMessage(`{"path":{}}`)
			}
			f.responses["sys/mounts/public-transit"] = setupMap(t, map[string]any{"type": "transit"})
			f.responses["public-transit/keys/sessions"] = setupMap(t, session)
			f.responses["public-transit/keys/work"] = setupMap(t, signing)
			f.responses["sys/mounts/worker-pki"] = setupMap(t, map[string]any{"type": "pki"})
			f.responses["worker-pki/cert/ca"] = setupMap(t, map[string]any{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.roots[0]}))})
			f.responses["worker-pki/roles/worker"] = setupMap(t, role)
			for _, r := range roles {
				f.responses["auth/owner-auth/role/"+r.Name] = setupMap(t, r.Role)
				f.responses["sys/policies/acl/"+r.Name] = setupMap(t, map[string]any{"name": r.Name, "policy": string(r.Policy)})
			}
			out, err := f.reader.VerifyOwnerPublic(context.Background(), in, f.profile)
			if (err == nil) != (mode == "valid") {
				t.Fatal(mode, err)
			}
			if err == nil && (out.Signing.Version != 2 || !bytes.Equal(out.Signing.PublicKey, public) || out.Signing.KeyID != "work-v2" || len(out.WorkerRoots) != 1 || !bytes.Equal(out.WorkerRoots[0], f.roots[0]) || out.Until.IsZero()) {
				t.Fatal("readback", out)
			}
		})
	}
}
