package integration

import (
	"crypto/tls"
	"net"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// publicRoleTLSConfig is the admin connection through the fixture TLS bridge.
func publicRoleTLSConfig(t *testing.T, admin *pgxpool.Pool, address string, tlsConfig *tls.Config) *pgx.ConnConfig {
	t.Helper()
	c := admin.Config().ConnConfig.Copy()
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		t.Fatal(e)
	}
	number, e := strconv.Atoi(port)
	if e != nil {
		t.Fatal(e)
	}
	c.Host, c.Port = host, uint16(number)
	c.TLSConfig = tlsConfig.Clone()
	c.TLSConfig.MinVersion = tls.VersionTLS13
	c.Fallbacks = nil
	c.ValidateConnect = nil
	c.AfterConnect = nil
	c.Tracer = nil
	return c
}
