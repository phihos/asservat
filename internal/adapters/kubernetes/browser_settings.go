package kubernetes

import (
	"context"
	"net/url"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/identity"
)

// Bootstrap pins an administrator-protected ConfigMap UID and the installation
// root. Public input cannot select a different configuration or credential.
type BrowserSettingsClient struct {
	client          *PermissionClient
	name, uid, root string
}

var _ app.BrowserSettingsReader = (*BrowserSettingsClient)(nil)

func NewBrowserSettingsClient(client *PermissionClient, name, uid, root string) (*BrowserSettingsClient, error) {
	if client == nil || !installationRefValid(name, uid) || !authorization.UUID(root) {
		return nil, value.ErrInvalid
	}
	return &BrowserSettingsClient{client, name, uid, root}, nil
}
func canonicalBrowserOrigin(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawPath == "" && u.RawQuery == "" && u.Fragment == "" && u.Opaque == "" && u.Host == strings.ToLower(u.Host) && u.Port() != "443" && len(s) <= 2048
}
func (c *BrowserSettingsClient) BrowserSettings(ctx context.Context) (value.BrowserSettings, error) {
	var zero value.BrowserSettings
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := c.client.now()
	data, ref, err := c.client.installationConfig(ctx, c.name, c.uid)
	if err != nil || len(data) != 1 || data["browser.json"] == "" {
		return zero, value.ErrUnavailable
	}
	var wire contracts.BrowserSettings
	digest, err := decodePermissionSpec([]byte(data["browser.json"]), c.client.validator.browserSchema, &wire)
	if err != nil || wire.RootID != c.root || !canonicalBrowserOrigin(wire.Origin) {
		return zero, value.ErrUnavailable
	}
	u, e := url.Parse(wire.Issuer)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return zero, value.ErrUnavailable
	}
	out := value.BrowserSettings{RootID: wire.RootID, Epoch: wire.SessionEpoch, Issuer: wire.Issuer, ClientID: wire.ClientID, Origin: wire.Origin, Revision: value.Revision{UID: ref.UID, Generation: wire.Revision, Digest: digest}, Suspended: wire.Suspended, MaxLifetimeSeconds: wire.MaxLifetimeSeconds, MaxLogins: wire.MaxLogins, MaxSessions: wire.MaxSessions, MaxLogoutEvents: wire.MaxLogoutEvents, ObservedAt: started, FreshUntil: started.Add(5 * time.Second)}
	if c.client.current(ctx, started, 5*time.Second) != nil || !out.Valid(c.client.now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}
