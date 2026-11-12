package integration

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestInstalledPermissionObserverPreservesOriginalVerifiedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.Host, config.ConnConfig.Database = host, "original-database"
	n, _ := strconv.Atoi(port)
	config.ConnConfig.Port = uint16(n)
	config.ConnConfig.User, config.ConnConfig.Password = "original-administrator", "original-private-observer"
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})) {
		t.Fatal("TLS roots")
	}
	config.ConnConfig.TLSConfig = &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS13}
	config.ConnConfig.Fallbacks = nil
	config.ConnConfig.RuntimeParams = map[string]string{"application_name": "original-observer"}
	config.MaxConns, config.MinConns = 2, 0
	admin, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	login := contracts.OwnerSQLCredential{Username: "actual-compiled-hub", Password: "original-compiled-password"}
	actual := installedPermissionObserverPoolConfig(t, admin, login)
	got, want := actual.ConnConfig, admin.Config().ConnConfig
	if got.Host != want.Host || got.Port != want.Port || got.Database != want.Database || got.TLSConfig.ServerName != want.TLSConfig.ServerName || got.TLSConfig.MinVersion != want.TLSConfig.MinVersion || got.TLSConfig.RootCAs != want.TLSConfig.RootCAs || got.TLSConfig.InsecureSkipVerify || !reflect.DeepEqual(got.Fallbacks, want.Fallbacks) || !reflect.DeepEqual(got.RuntimeParams, want.RuntimeParams) || actual.MaxConns != 1 || got.User != login.Username || got.Password != login.Password {
		t.Fatal("permission reader replaced the original verified transport/database or compiled identity")
	}
	if admin.Config().ConnConfig.User != "original-administrator" || admin.Config().MaxConns != 2 {
		t.Fatal("original observer mutated")
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: got.TLSConfig}, Timeout: server.Client().Timeout}
	defer client.CloseIdleConnections()
	response, err := client.Get("https://" + net.JoinHostPort(got.Host, strconv.Itoa(int(got.Port))))
	if err != nil {
		t.Fatal("original verified TLS route unavailable", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("original TLS endpoint replaced")
	}
}
