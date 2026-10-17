package providerconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"asservat.local/asservat/internal/contracts"
	"k8s.io/apimachinery/pkg/util/validation"
)

// This fixed message never includes rejected credential content or a decoder
// diagnostic. Docker helpers and identity tokens require an explicit supported
// username/password config; no external command or credential discovery occurs.
var ErrInitialRegistry = errors.New("registry input must contain one pinned registry and username/password auth; credential helpers, identity tokens, additional registries and unknown fields are unsupported")

// NormalizeInitialRegistry validates supplied private input only. It is not
// registry authentication, image verification or installation authority.
func NormalizeInitialRegistry(image string, raw []byte) ([]byte, error) {
	registry, ok := initialImageRegistry(image)
	if !ok || len(raw) == 0 || len(raw) > contracts.InitialRegistryMaxBytes || !jsontext.Value(raw).IsValid() {
		return nil, ErrInitialRegistry
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || len(top) != 1 || top["auths"] == nil {
		return nil, ErrInitialRegistry
	}
	var auths map[string]json.RawMessage
	if json.Unmarshal(top["auths"], &auths) != nil || len(auths) != 1 {
		return nil, ErrInitialRegistry
	}
	var fields map[string]json.RawMessage
	for host, entry := range auths {
		// The single historical Docker Hub authority alias is explicit. No
		// scheme, wildcard, path or unrelated authority can match other hosts.
		if registry == "docker.io" && (host == "https://index.docker.io/v1/" || host == "index.docker.io") {
			host = "docker.io"
		}
		if host != registry || json.Unmarshal(entry, &fields) != nil || len(fields) == 0 {
			return nil, ErrInitialRegistry
		}
	}
	values := map[string]string{}
	for key, value := range fields {
		if key != "username" && key != "password" && key != "auth" && key != "email" {
			return nil, ErrInitialRegistry
		}
		var s string
		if json.Unmarshal(value, &s) != nil || !initialRegistryText(s, contracts.InitialRegistryMaxBytes) {
			return nil, ErrInitialRegistry
		}
		values[key] = s
	}
	if email, exists := values["email"]; exists && !initialRegistryText(email, 254) {
		return nil, ErrInitialRegistry
	}
	username, hasUsername := values["username"]
	password, hasPassword := values["password"]
	if hasUsername != hasPassword {
		return nil, ErrInitialRegistry
	}
	if auth, exists := values["auth"]; exists {
		decoded, err := base64.StdEncoding.DecodeString(auth)
		defer clear(decoded)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != auth {
			return nil, ErrInitialRegistry
		}
		u, p, found := strings.Cut(string(decoded), ":")
		if !found || hasUsername && (username != u || password != p) {
			return nil, ErrInitialRegistry
		}
		username, password = u, p
	}
	if !initialRegistryText(username, 256) || strings.Contains(username, ":") || !initialRegistryText(password, 2048) {
		return nil, ErrInitialRegistry
	}
	// Preserve only the fixed pair understood by kubelet. Standard optional
	// email and redundant fields are discarded, never copied into public data.
	value := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	out, err := json.Marshal(map[string]any{"auths": map[string]any{registry: map[string]string{"auth": value}}})
	if err != nil || len(out) > contracts.InitialRegistryMaxBytes {
		clear(out)
		return nil, ErrInitialRegistry
	}
	return out, nil
}

// InitialRegistryMaterial requires already-normalized retained bytes and an
// exact explicit capability. Omission never accepts private registry material.
func InitialRegistryMaterial(image, capability string, raw []byte) bool {
	if capability == "" {
		return len(raw) == 0
	}
	if capability != contracts.InitialRegistryAuthentication {
		return false
	}
	normal, err := NormalizeInitialRegistry(image, raw)
	defer clear(normal)
	return err == nil && bytes.Equal(normal, raw)
}

func initialRegistryText(s string, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for i := range s {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}

func initialImageRegistry(image string) (string, bool) {
	repository, digest, ok := strings.Cut(image, "@sha256:")
	if !ok || len(repository) > 384 || len(digest) != 64 || strings.ToLower(digest) != digest {
		return "", false
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", false
	}
	host, path, ok := strings.Cut(repository, "/")
	if !ok || path == "" || strings.ContainsAny(repository, " @?\\#\t\r\n") {
		return "", false
	}
	// Require the registry to be explicit; Docker's implicit library/default
	// namespace interpretation is not a credential-routing input.
	if !strings.ContainsAny(host, ".:") && host != "localhost" {
		return "", false
	}
	dns := host
	if strings.Contains(host, ":") {
		var port string
		var err error
		dns, port, err = net.SplitHostPort(host)
		n, parseErr := strconv.Atoi(port)
		if err != nil || parseErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", false
		}
	}
	if _, err := netip.ParseAddr(dns); err != nil && len(validation.IsDNS1123Subdomain(dns)) != 0 {
		return "", false
	}
	if host == "index.docker.io" {
		host = "docker.io"
	}
	return host, true
}
