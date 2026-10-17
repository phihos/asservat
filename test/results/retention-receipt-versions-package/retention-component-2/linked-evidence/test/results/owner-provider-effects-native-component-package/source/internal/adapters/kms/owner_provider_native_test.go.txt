package kms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// Real Kubernetes TokenReview and the pinned external Bao supply these provider
// observations. Namespace/account/PKI setup is owned privileged fixture work;
// it is not the installed protected source/SQL proof, an owner process, kubelet
// token rotation, or the separately pending original 600s expiry qualification.
func TestOwnerProviderAuthenticationWithRealKubernetesAndOpenBao(t *testing.T) {
	f := newOwnerProviderNativeFixture(t)
	if !f.run(t, "four-standard-logins-and-renewals", func(t *testing.T) {
		for i, entry := range f.recipe.Roles {
			start := time.Now()
			credential, err := f.controls[i].login(f.ctx, f.jwt)
			if err != nil {
				t.Fatalf("actual %s login/self lookup unavailable: %v", entry.Purpose, err)
			}
			f.credentials[i] = credential
			originalUntil, originalIssue, originalHard, originalJWT := credential.until, credential.issued, credential.hardUntil, credential.jwtUntil
			renewed, err := f.controls[i].renew(f.ctx, credential)
			if err != nil {
				t.Fatalf("actual %s renewal/self lookup unavailable: %v", entry.Purpose, err)
			}
			if !credential.until.Equal(originalUntil) || !renewed.issued.Equal(originalIssue) || !renewed.hardUntil.Equal(originalHard) || !renewed.jwtUntil.Equal(originalJWT) || !bytes.Equal(credential.token, renewed.token) {
				t.Fatal("provider renewal replaced immutable original identity or old observation")
			}
			f.credentials[i] = renewed
			credential.destroy()
			t.Logf("%s actual standard login+renewal %.3fs; acknowledged lease %.3fs, unchanged issue/hard/JWT bounds", entry.Purpose, time.Since(start).Seconds(), time.Until(renewed.until).Seconds())
		}
	}) {
		return
	}
	if !f.run(t, "first-effects-and-cross-purpose-denials", func(t *testing.T) { f.firstEffects(t) }) {
		return
	}
	if !f.run(t, "leased-maintained-effects-and-joined-retirement", func(t *testing.T) { f.leasedEffects(t) }) {
		return
	}
	if !f.run(t, "wrong-audience-and-added-policy-denied", func(t *testing.T) {
		wrong := f.token(f.owner, f.pod, []string{"https://wrong.invalid/owner-provider"})
		defer clear(wrong)
		if credential, err := f.controls[0].login(f.ctx, wrong); err == nil || credential != nil {
			t.Fatal("provider accepted wrong bound audience")
		}
		var changed map[string]any
		if json.Unmarshal(f.recipe.Roles[0].Role, &changed) != nil {
			t.Fatal("generated auth role")
		}
		changed["token_policies"] = []string{f.recipe.Roles[0].Name, "default"}
		f.admin(http.MethodPost, "auth/owner-auth/role/"+f.recipe.Roles[0].Name, changed, 204)
		if credential, err := f.controls[0].login(f.ctx, f.jwt); err == nil || credential != nil {
			t.Fatal("additional provider policy became usable")
		}
		f.admin(http.MethodPost, "auth/owner-auth/role/"+f.recipe.Roles[0].Name, json.RawMessage(f.recipe.Roles[0].Role), 204)
	}) {
		return
	}
	if !f.run(t, "deleted-original-pod-denies-renewal-fresh-token-logs-in", func(t *testing.T) {
		f.deletePod(f.pod)
		// Read-only confirmation distinguishes actual API state from a presumed
		// instantaneous revocation promise. No repeated provider renewal occurs.
		until := time.Now().Add(15 * time.Second)
		for {
			observation, err := f.api.AuthenticationV1().TokenReviews().Create(f.ctx, &auth.TokenReview{Spec: auth.TokenReviewSpec{Token: string(f.jwt), Audiences: []string{contracts.OwnerProviderAudience(f.input.InstallationID, f.input.ClusterID)}}}, meta.CreateOptions{})
			if err != nil {
				t.Fatal("original bound TokenReview", err)
			}
			if !observation.Status.Authenticated {
				break
			}
			if !time.Now().Before(until) {
				t.Fatal("original Pod deletion was not observed within fixture bound")
			}
			select {
			case <-f.ctx.Done():
				t.Fatal(f.ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
		old := f.credentials[0]
		originalEnd := old.until
		if result, err := f.controls[0].renew(f.ctx, old); err == nil || result != nil {
			t.Fatal("old provider token renewed after original bound Pod rejection")
		}
		if !old.until.Equal(originalEnd) {
			t.Fatal("failed renewal changed old usable end")
		}
		f.pod = f.createPod("replacement", f.owner.Name)
		freshJWT := f.token(f.owner, f.pod, []string{contracts.OwnerProviderAudience(f.input.InstallationID, f.input.ClusterID)})
		fresh, err := f.controls[0].login(f.ctx, freshJWT)
		if err != nil {
			clear(freshJWT)
			t.Fatal("fresh same-account Pod token login", err)
		}
		if fresh.accessor == old.accessor || bytes.Equal(fresh.token, old.token) {
			t.Fatal("new authentication adopted old provider credential")
		}
		_ = f.controls[0].revoke(f.ctx, old)
		old.destroy()
		f.credentials[0] = fresh
		clear(f.jwt)
		f.jwt = freshJWT
		t.Log("old submitted JWT no longer renews; new real Pod/token on the same original SA logs in. This is Pod-deletion behavior, not 600s expiration or installed original-Pod authority.")
	}) {
		return
	}
	if !f.run(t, "external-reviewer-rotation", func(t *testing.T) {
		old := f.reviewerPod
		f.reviewerPod = f.createPod("reviewer-next", f.reviewer.Name)
		next := f.token(f.reviewer, f.reviewerPod, nil)
		defer clear(next)
		f.configureReviewer(string(next))
		f.deletePod(old)
		credential, err := f.controls[0].login(f.ctx, f.jwt)
		if err != nil {
			t.Fatal("login after operator-owned reviewer rotation", err)
		}
		defer credential.destroy()
		if err = f.controls[0].revoke(f.ctx, credential); err != nil {
			t.Fatal("new provider token retirement", err)
		}
	}) {
		return
	}
	f.run(t, "recreated-account-does-not-replace-original-uid", func(t *testing.T) {
		if err := f.api.CoreV1().ServiceAccounts(f.namespace).Delete(f.ctx, f.owner.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: ptr.To(f.owner.UID)}}); err != nil {
			t.Fatal(err)
		}
		recreated, err := f.api.CoreV1().ServiceAccounts(f.namespace).Create(f.ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: f.owner.Name}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
		if err != nil || recreated.UID == f.owner.UID {
			t.Fatal("recreated account fixture", err)
		}
		pod := f.createPod("recreated", recreated.Name)
		jwt := f.token(recreated, pod, []string{contracts.OwnerProviderAudience(f.input.InstallationID, f.input.ClusterID)})
		defer clear(jwt)
		if credential, err := f.controls[0].login(f.ctx, jwt); err == nil || credential != nil {
			t.Fatal("name-only provider role replaced original account UID")
		}
	})
}

func (f *ownerProviderNativeFixture) firstEffects(t *testing.T) {
	t.Helper()
	f.admin(http.MethodPost, "sys/mounts/"+f.input.KeyService.AuditMount, map[string]string{"type": "transit"}, 204)
	f.admin(http.MethodPost, f.input.KeyService.AuditMount+"/keys/"+f.input.KeyService.AuditKey, map[string]string{"type": "aes256-gcm96"}, 200)
	f.admin(http.MethodPost, "sys/mounts/"+f.input.KeyService.PKIMount, map[string]string{"type": "pki"}, 204)
	f.admin(http.MethodPost, f.input.KeyService.PKIMount+"/root/generate/internal", map[string]any{"common_name": "synthetic-provider-auth-root", "ttl": "1h", "key_type": "ec", "key_bits": 256}, 200)
	for _, purpose := range []string{"server", "client"} {
		role := map[string]any{"require_cn": false, "use_csr_common_name": false, "use_csr_sans": false, "allow_ip_sans": false, "allow_localhost": false, "allowed_domains": []string{"owner.provider.invalid"}, "allow_bare_domains": true, "key_type": "ec", "key_bits": 256, "server_flag": purpose == "server", "client_flag": purpose == "client", "code_signing_flag": false, "email_protection_flag": false, "key_usage": []string{"DigitalSignature"}, "ext_key_usage": []string{}, "basic_constraints_valid_for_non_ca": true, "not_before_duration": "30s", "max_ttl": "20m", "ttl": "20m"}
		f.admin(http.MethodPost, f.input.KeyService.PKIMount+"/roles/"+purpose, role, 200)
	}
	plain := []byte("synthetic owner audit key material")
	encrypted := f.effect(t, 0, f.input.KeyService.AuditMount+"/encrypt/"+f.input.KeyService.AuditKey, map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plain)}, 200)
	data, ok := encrypted["data"].(map[string]any)
	if !ok {
		t.Fatal("Transit encryption data")
	}
	ciphertext, ok := data["ciphertext"].(string)
	if !ok || ciphertext == "" {
		t.Fatal("Transit ciphertext")
	}
	opened := f.effect(t, 1, f.input.KeyService.AuditMount+"/decrypt/"+f.input.KeyService.AuditKey, map[string]string{"ciphertext": ciphertext}, 200)
	data, ok = opened["data"].(map[string]any)
	if !ok {
		t.Fatal("Transit decryption data")
	}
	encoded, ok := data["plaintext"].(string)
	if !ok {
		t.Fatal("Transit plaintext")
	}
	actual, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || !bytes.Equal(actual, plain) {
		t.Fatal("separated audit key effects failed")
	}
	clear(actual)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	sign := map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "alt_names": "owner.provider.invalid", "ttl": "20m"}
	for i, purpose := range []string{"server", "client"} {
		result := f.effect(t, i+2, f.input.KeyService.PKIMount+"/sign/"+purpose, sign, 200)
		data, ok := result["data"].(map[string]any)
		if !ok {
			t.Fatal("PKI result")
		}
		encoded, ok := data["certificate"].(string)
		if !ok {
			t.Fatal("PKI certificate")
		}
		block, _ := pem.Decode([]byte(encoded))
		if block == nil {
			t.Fatal("PKI PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		want := x509.ExtKeyUsageServerAuth
		if purpose == "client" {
			want = x509.ExtKeyUsageClientAuth
		}
		if len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != want {
			t.Fatal("provider purpose expanded certificate usage")
		}
	}
	paths := []string{f.input.KeyService.AuditMount + "/encrypt/" + f.input.KeyService.AuditKey, f.input.KeyService.AuditMount + "/decrypt/" + f.input.KeyService.AuditKey, f.input.KeyService.PKIMount + "/sign/server", f.input.KeyService.PKIMount + "/sign/client"}
	bodies := []any{map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plain)}, map[string]string{"ciphertext": ciphertext}, sign, sign}
	for i := range f.credentials {
		for j, path := range paths {
			if i != j {
				f.effect(t, i, path, bodies[j], 403)
			}
		}
		f.effect(t, i, "auth/token/create", map[string]string{}, 403)
	}
	t.Log("real generated four-purpose ACLs permit their first exact Transit/PKI effect and deny every other purpose and token creation; no installed effect authority inferred")
}

func (f *ownerProviderNativeFixture) effect(t *testing.T, purpose int, path string, body any, want int) map[string]any {
	t.Helper()
	credential := f.credentials[purpose]
	transport := &ownerProviderLeaseTransport{base: f.http.Transport, now: time.Now, source: func(context.Context) (ownerProviderLease, error) {
		return ownerProviderLease{token: bytes.Clone(credential.token), until: credential.until, release: func() {}}, nil
	}}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	call, end := context.WithTimeout(f.ctx, 5*time.Second)
	defer end()
	request, err := http.NewRequestWithContext(call, http.MethodPost, f.input.KeyService.Endpoint+"/v1/"+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal("actual finite provider effect unavailable", path, err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("purpose %d %s status %d, want %d", purpose, path, response.StatusCode, want)
	}
	if want == 403 {
		return nil
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	defer clear(encoded)
	var out map[string]any
	if err != nil || len(encoded) > 32768 || json.Unmarshal(encoded, &out) != nil {
		t.Fatal("actual provider effect reply invalid", path)
	}
	return out
}
