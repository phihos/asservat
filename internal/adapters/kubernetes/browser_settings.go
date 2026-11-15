package kubernetes

import (
	"context"
	"net/url"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/identity"
)

// BrowserSettingsReader reads browser.json from the Helm-rendered ConfigMap
// pinned by name and UID. Public input cannot select another configuration.
type BrowserSettingsReader struct {
	client    *PermissionClient
	name, uid string
}

func NewBrowserSettingsReader(client *PermissionClient, name, uid string) (*BrowserSettingsReader, error) {
	if client == nil || !installationRefValid(name, uid) {
		return nil, value.ErrInvalid
	}
	return &BrowserSettingsReader{client, name, uid}, nil
}

func canonicalBrowserOrigin(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawPath == "" && u.RawQuery == "" && u.Fragment == "" && u.Opaque == "" && u.Host == strings.ToLower(u.Host) && u.Port() != "443" && len(s) <= 2048
}

func (c *BrowserSettingsReader) BrowserSettings(ctx context.Context) (value.BrowserSettings, error) {
	var zero value.BrowserSettings
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	data, _, err := c.client.installationConfig(ctx, c.name, c.uid)
	if err != nil || len(data) != 1 || data["browser.json"] == "" {
		return zero, value.ErrUnavailable
	}
	wire := contracts.BrowserSettings{MaxLifetimeSeconds: 604800, InactivityTimeoutSeconds: 86400}
	if _, err = decodePermissionSpec([]byte(data["browser.json"]), c.client.validator.browserSchema, &wire); err != nil || !canonicalBrowserOrigin(wire.Origin) {
		return zero, value.ErrUnavailable
	}
	u, e := url.Parse(wire.Issuer)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return zero, value.ErrUnavailable
	}
	out := value.BrowserSettings{Issuer: wire.Issuer, ClientID: wire.ClientID, Origin: wire.Origin, MaxLifetime: time.Duration(wire.MaxLifetimeSeconds) * time.Second, InactivityTimeout: time.Duration(wire.InactivityTimeoutSeconds) * time.Second}
	if !out.Valid() {
		return zero, value.ErrUnavailable
	}
	return out, nil
}
