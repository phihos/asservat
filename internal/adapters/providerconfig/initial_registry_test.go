package providerconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestInitialRegistryClosedSingleImageMaterial(t *testing.T) {
	image := "registry.example:5443/asservat@sha256:" + strings.Repeat("a", 64)
	encode := func(v any) []byte {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	config := func(host string, entry any) []byte {
		return encode(map[string]any{"auths": map[string]any{host: entry}})
	}
	auth := base64.StdEncoding.EncodeToString([]byte("user:private:password"))
	want := config("registry.example:5443", map[string]string{"auth": auth})
	for _, entry := range []any{
		map[string]string{"auth": auth},
		map[string]string{"username": "user", "password": "private:password"},
		map[string]string{"username": "user", "password": "private:password", "auth": auth, "email": "user@example.invalid"},
	} {
		got, e := NormalizeInitialRegistry(image, config("registry.example:5443", entry))
		if e != nil || !bytes.Equal(got, want) || !InitialRegistryMaterial(image, contracts.InitialRegistryAuthentication, got) {
			t.Fatal("explicit single-registry pair was not normalized")
		}
	}
	for label, raw := range map[string][]byte{
		"other-registry":   config("other.example", map[string]string{"auth": auth}),
		"wildcard":         config("*.example", map[string]string{"auth": auth}),
		"path":             config("registry.example:5443/project", map[string]string{"auth": auth}),
		"scheme":           config("https://registry.example:5443", map[string]string{"auth": auth}),
		"helper":           []byte(`{"auths":{},"credsStore":"external"}`),
		"entry-helper":     config("registry.example:5443", map[string]string{"auth": auth, "identitytoken": "private"}),
		"headers":          []byte(`{"auths":{},"HttpHeaders":{}}`),
		"duplicate":        []byte(`{"auths":{},"auths":{}}`),
		"duplicate-entry":  []byte(`{"auths":{"registry.example:5443":{"auth":"dTpw","auth":"dTpx"}}}`),
		"case-alias":       []byte(`{"Auths":{"registry.example:5443":{"auth":"dTpw"}}}`),
		"two-registries":   []byte(`{"auths":{"registry.example:5443":{"auth":"dTpw"},"other.example":{"auth":"dTpw"}}}`),
		"contradictory":    config("registry.example:5443", map[string]string{"auth": auth, "username": "other", "password": "private"}),
		"half-pair":        config("registry.example:5443", map[string]string{"auth": auth, "username": "user"}),
		"missing-password": config("registry.example:5443", map[string]string{"auth": "dTo="}),
		"newline":          config("registry.example:5443", map[string]string{"username": "user", "password": "private\n"}),
		"oversize":         []byte(strings.Repeat(" ", contracts.InitialRegistryMaxBytes+1)),
		"null":             []byte(`{"auths":null}`),
	} {
		t.Run(label, func(t *testing.T) {
			if out, e := NormalizeInitialRegistry(image, raw); e != ErrInitialRegistry || out != nil {
				t.Fatal("unsupported credential shape accepted")
			}
		})
	}
	if InitialRegistryMaterial(image, "", want) || InitialRegistryMaterial(image, "unknown", want) || InitialRegistryMaterial(image, contracts.InitialRegistryAuthentication, nil) {
		t.Fatal("capability/material mismatch accepted")
	}
	if !InitialRegistryMaterial(image, "", nil) {
		t.Fatal("legacy omission changed")
	}
	if _, e := NormalizeInitialRegistry("project/image@sha256:"+strings.Repeat("a", 64), want); e == nil {
		t.Fatal("implicit image registry accepted")
	}
	if strings.Contains(ErrInitialRegistry.Error(), "private:password") {
		t.Fatal("error exposed credential")
	}
}

func TestInitialRegistryDockerHubAliasIsNotGeneralURLMatching(t *testing.T) {
	image := "docker.io/org/asservat@sha256:" + strings.Repeat("b", 64)
	got, e := NormalizeInitialRegistry(image, []byte(`{"auths":{"https://index.docker.io/v1/":{"auth":"dTpw"}}}`))
	if e != nil || string(got) != `{"auths":{"docker.io":{"auth":"dTpw"}}}` {
		t.Fatal("explicit Docker Hub alias failed")
	}
	if _, e = NormalizeInitialRegistry(image, []byte(`{"auths":{"https://docker.io/v1/":{"auth":"dTpw"}}}`)); e == nil {
		t.Fatal("unlisted authority alias accepted")
	}
}
