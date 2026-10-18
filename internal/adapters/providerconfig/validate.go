// Package providerconfig validates public provider configuration and generates
// pure setup recipes. Its separate installation-only SetupReader performs bounded
// named reads; it never mutates providers, issues credentials or grants authority.
package providerconfig

import (
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

var providerName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func validHost(host string) bool {
	if addr, e := netip.ParseAddr(host); e == nil {
		return addr.Zone() == ""
	}
	return len(host) <= 253 && len(validation.IsDNS1123Subdomain(strings.ToLower(host))) == 0
}
func validEndpoint(endpoint string) bool {
	u, e := url.Parse(endpoint)
	if e != nil || len(endpoint) > 2048 || u.Scheme != "https" || !validHost(u.Hostname()) || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(endpoint, "#") || u.RawPath != "" || u.Path != "" && u.Path != "/" || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if u.Port() != "" {
		port, e := strconv.Atoi(u.Port())
		if e != nil || port < 1 || port > 65535 {
			return false
		}
	}
	return true
}

// Validate checks syntax, bounds and current DER CA anchors. Endpoint presence,
// remote roles/permissions, connectivity and fresh authority remain separate
// runtime checks; this does not claim readiness or issue trial mutations.
func Validate(k contracts.OwnerProviderEndpoint, p contracts.OwnerPostgresEndpoint, a contracts.OwnerAuditStore, key contracts.ConfigurationKeyService, now time.Time) error {
	for _, v := range []contracts.OwnerProviderEndpoint{k, {Endpoint: a.Endpoint, Roots: a.Roots}, {Endpoint: key.Endpoint, Roots: key.Roots}} {
		if !validEndpoint(v.Endpoint) {
			return cfg.ErrInvalid
		}
		if _, _, e := mtls.OwnerTrustRoots(v.Roots, now); e != nil {
			return cfg.ErrInvalid
		}
	}
	if !validHost(p.Host) || !identity.Text(p.Database, 63) || p.Port < 1 || p.Port > 65535 || p.MaxConnections < 1 || p.MaxConnections > 4 {
		return cfg.ErrInvalid
	}
	if _, _, e := mtls.OwnerTrustRoots(p.Roots, now); e != nil {
		return cfg.ErrInvalid
	}
	if !identity.Text(a.Region, 128) || !identity.Text(a.Bucket, 63) || !providerName.MatchString(key.AuditMount) || !providerName.MatchString(key.AuditKey) {
		return cfg.ErrInvalid
	}
	return nil
}

// ValidateStore checks one object store's endpoint, current DER CA anchors,
// region and bucket, as Validate checks the audit store.
func ValidateStore(a contracts.OwnerAuditStore, now time.Time) error {
	if !validEndpoint(a.Endpoint) || !identity.Text(a.Region, 128) || !identity.Text(a.Bucket, 63) {
		return cfg.ErrInvalid
	}
	if _, _, e := mtls.OwnerTrustRoots(a.Roots, now); e != nil {
		return cfg.ErrInvalid
	}
	return nil
}
