package contracts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestOwnerProviderAuthenticationWireRejectsExtraAuthorityAndAliases(t *testing.T) {
	p := OwnerProviderAuthentication{Format: OwnerProviderAuthenticationFormat, AuthMount: "owner-auth", AuthMountAccessor: "auth_kubernetes_original", ServiceAccount: WorkerObjectReference{Name: "owner", UID: "10000000-0000-4000-8000-000000000001"}, AuditCredentials: WorkerObjectReference{Name: "audit", UID: "10000000-0000-4000-8000-000000000002"}, RecipeSHA256: strings.Repeat("a", 64)}
	b, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeOwnerProviderAuthentication(bytes.NewReader(b))
	if e != nil || got != p {
		t.Fatal("closed public profile", e)
	}
	for name, bad := range map[string][]byte{
		"token":           append(append([]byte{}, b[:len(b)-1]...), []byte(`,"token":"secret"}`)...),
		"role":            append(append([]byte{}, b[:len(b)-1]...), []byte(`,"role":"arbitrary"}`)...),
		"ttl":             append(append([]byte{}, b[:len(b)-1]...), []byte(`,"tokenTTL":90000}`)...),
		"reviewer":        append(append([]byte{}, b[:len(b)-1]...), []byte(`,"reviewer":"secret"}`)...),
		"alias":           bytes.Replace(b, []byte(`"authMount"`), []byte(`"AuthMount"`), 1),
		"duplicate":       append(append([]byte{}, b[:len(b)-1]...), []byte(`,"authMount":"owner-auth"}`)...),
		"missing-account": bytes.Replace(b, []byte(`"serviceAccount":`), []byte(`"account":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeOwnerProviderAuthentication(bytes.NewReader(bad)); e == nil {
				t.Fatal("unsupported runtime authority field accepted")
			}
		})
	}
}

func TestOwnerProviderAuthenticationCannotBeIgnoredByLegacyDeployment(t *testing.T) {
	// Zero-valued public fields are sufficient for the closed wire-shape check;
	// runtime validity is independent. Baseline omission decodes successfully.
	v := OwnerDeployment{}
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeOwnerDeployment(bytes.NewReader(b)); e != nil {
		t.Fatal("legacy omission changed", e)
	}
	bad := append(append([]byte{}, b[:len(b)-1]...), []byte(`,"providerAuthentication":{"format":"asservat-owner-kubernetes-auth/v1"}}`)...)
	if _, e = DecodeOwnerDeployment(bytes.NewReader(bad)); e == nil {
		t.Fatal("legacy deployment can silently ignore unimplemented provider selection")
	}
}
