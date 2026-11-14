package providerconfig

import (
	"net/http"
	"net/url"
)

// Test-only endpoint mapping keeps the selected production URL/profile intact
// while using the existing real-TLS synthetic readback fixture.
type bundledSetupFixtureTransport struct {
	upstream http.RoundTripper
	target   *url.URL
}

func (t bundledSetupFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	request := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = t.target.Scheme
	u.Host = t.target.Host
	request.URL = &u
	request.Host = t.target.Host
	return t.upstream.RoundTrip(request)
}
func (t bundledSetupFixtureTransport) CloseIdleConnections() {
	if c, ok := t.upstream.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
