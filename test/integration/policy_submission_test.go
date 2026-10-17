package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// The real identity and nonexportable provider key are exercised here. Signing
// trust/source/scope are synthetic private inputs; this grants no collection.
type submissionFixtureTrust struct{ value value.SubmissionTrust }

func (s *submissionFixtureTrust) SubmissionTrust(context.Context) (value.SubmissionTrust, error) {
	out := s.value
	out.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	out.FreshUntil = out.ObservedAt.Add(5 * time.Second)
	return out, nil
}

func testProviderPolicySubmission(t *testing.T, endpoint string, client *http.Client, actor identity.Identity) {
	t.Helper()
	ctx := context.Background()
	request := func(method, path, token string, body any, want int) map[string]any {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded, _ = json.Marshal(body)
		}
		r, e := http.NewRequestWithContext(ctx, method, endpoint+"/v1/"+path, bytes.NewReader(encoded))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("X-Vault-Token", token)
		r.Header.Set("Content-Type", "application/json")
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal("synthetic signing fixture HTTP failure")
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("signing fixture %s %s status %d; wanted %d", method, path, resp.StatusCode, want)
		}
		if want == 204 || want == 403 {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32768))
			return nil
		}
		var out map[string]any
		if json.NewDecoder(io.LimitReader(resp.Body, 32768)).Decode(&out) != nil {
			t.Fatal("signing fixture JSON")
		}
		return out
	}
	request("POST", "sys/mounts/submission-transit", "synthetic-root", map[string]any{"type": "transit"}, 204)
	request("POST", "submission-transit/keys/policy", "synthetic-root", map[string]any{"type": "ed25519", "exportable": false, "allow_plaintext_backup": false}, 200)
	public := func(version string) ed25519.PublicKey {
		t.Helper()
		r := request("GET", "submission-transit/keys/policy", "synthetic-root", nil, 200)
		key := r["data"].(map[string]any)["keys"].(map[string]any)[version].(map[string]any)["public_key"].(string)
		b, e := base64.StdEncoding.DecodeString(key)
		if e != nil || len(b) != 32 {
			t.Fatal("provider public key")
		}
		return ed25519.PublicKey(b)
	}
	pub := public("1")
	request("PUT", "sys/policies/acl/submission-sign-only", "synthetic-root", map[string]string{"policy": `path "submission-transit/sign/policy" { capabilities = ["update"] }`}, 204)
	r := request("POST", "auth/token/create", "synthetic-root", map[string]any{"policies": []string{"submission-sign-only"}, "no_default_policy": true, "ttl": "5m", "renewable": false}, 200)
	token := r["auth"].(map[string]any)["client_token"].(string)
	key, e := kms.NewSigningKey(endpoint, token, "submission-transit", "policy", 1, pub, client)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if !actor.Valid(now) {
		t.Fatal("real browser identity expired before submission")
	}
	intent := value.PolicySubmissionIntent{RootID: "75000000-0000-4000-8000-000000000001", InstallationID: "75000000-0000-4000-8000-000000000002", IssuerEpoch: "75000000-0000-4000-8000-000000000003", Nonce: "75000000-0000-4000-8000-000000000004", Actor: actor.Principal, Source: identity.Revision{UID: "synthetic-persisted-policy", Generation: 1, Digest: artifact.Digest{1}}, ClusterID: "75000000-0000-4000-8000-000000000005", NamespaceUID: "synthetic-namespace", Name: "synthetic-policy", ScopeDigest: artifact.Digest{2}, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second)}
	trust := &submissionFixtureTrust{value: value.SubmissionTrust{RootID: intent.RootID, InstallationID: intent.InstallationID, IssuerEpoch: intent.IssuerEpoch, Revision: identity.Revision{UID: "synthetic-submission-trust", Generation: 1, Digest: artifact.Digest{3}}, Keys: []value.SubmissionKey{{ID: "version-1", PublicKey: pub, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}}}}
	signer, e := jose.NewPolicySubmissions(intent.RootID, intent.InstallationID, intent.IssuerEpoch, "version-1", trust, key.ForContext, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	verifier, e := jose.NewPolicySubmissions(intent.RootID, intent.InstallationID, intent.IssuerEpoch, "", trust, nil, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	signed, e := signer.SignPolicySubmission(ctx, intent)
	if e != nil {
		t.Fatal(e)
	}
	checked, e := verifier.VerifyPolicySubmission(ctx, signed, intent)
	if e != nil || checked.Submission.Actor != actor.Principal || !checked.Valid(time.Now()) {
		t.Fatal("real provider submission verification failed", e)
	}
	for _, path := range []string{"submission-transit/keys/policy", "submission-transit/export/signing-key/policy/1"} {
		request("GET", path, token, nil, 403)
	}
	request("POST", "submission-transit/keys/policy/rotate", token, map[string]any{}, 403)
	request("POST", "browser-transit/decrypt/sessions", token, map[string]any{}, 403)
	// Version 1 remains pinned after provider rotation, until explicit retirement.
	request("POST", "submission-transit/keys/policy/rotate", "synthetic-root", map[string]any{}, 200)
	again, e := signer.SignPolicySubmission(ctx, intent)
	if e != nil || !bytes.Equal(again, signed) {
		t.Fatal("rotation silently switched signing key", e)
	}
	request("POST", "submission-transit/keys/policy/config", "synthetic-root", map[string]any{"min_encryption_version": 2}, 200)
	if _, e := signer.SignPolicySubmission(ctx, intent); e == nil {
		t.Fatal("retired provider key signed")
	}
	pub2 := public("2")
	trust.value.Revision.Generation++
	trust.value.Revision.Digest[0]++
	trust.value.Keys = []value.SubmissionKey{{ID: "version-2", PublicKey: pub2, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}}
	if _, e := verifier.VerifyPolicySubmission(ctx, signed, intent); e == nil {
		t.Fatal("removed public signing key remained accepted")
	}
	key2, e := kms.NewSigningKey(endpoint, token, "submission-transit", "policy", 2, pub2, client)
	if e != nil {
		t.Fatal(e)
	}
	signer2, e := jose.NewPolicySubmissions(intent.RootID, intent.InstallationID, intent.IssuerEpoch, "version-2", trust, key2.ForContext, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	newSignature, e := signer2.SignPolicySubmission(ctx, intent)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := verifier.VerifyPolicySubmission(ctx, newSignature, intent); e != nil {
		t.Fatal(e)
	}
	t.Log("real browser identity, JWS through nonexportable OpenBao key, sign-only ACL, explicit versions, provider retirement and current-key revocation passed")
}
