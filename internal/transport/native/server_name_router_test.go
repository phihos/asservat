package native

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// ADR-190 step 6: each server name reaches its own unchanged TLS server with
// the ClientHello replayed; unknown names and non-TLS bytes are closed.
func TestServerNameRouterSplitsByClientHello(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"native.synthetic.invalid", "observation.synthetic.invalid", "other.synthetic.invalid"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	roots := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(der)
	roots.AddCert(leaf)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	router, err := NewServerNameRouter(ctx, raw, "native.synthetic.invalid", "observation.synthetic.invalid")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- router.Run() }()
	for _, name := range []string{"native.synthetic.invalid", "observation.synthetic.invalid"} {
		child := tls.NewListener(router.Listener(name), &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
		go func() {
			for {
				c, e := child.Accept()
				if e != nil {
					return
				}
				go func() { defer c.Close(); _, _ = c.Write([]byte(name)) }()
			}
		}()
	}
	for _, name := range []string{"native.synthetic.invalid", "observation.synthetic.invalid", "other.synthetic.invalid"} {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", raw.Addr().String(), &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS13})
		if name == "other.synthetic.invalid" {
			if err == nil {
				c.Close()
				t.Fatal("unknown server name routed")
			}
			continue
		}
		if err != nil {
			t.Fatal(name, err)
		}
		got, _ := io.ReadAll(c)
		c.Close()
		if string(got) != name {
			t.Fatalf("%s reached %q", name, got)
		}
	}
	plain, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = plain.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	_ = plain.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, _ := plain.Read(make([]byte, 1)); n != 0 {
		t.Fatal("non-TLS bytes answered")
	}
	plain.Close()
	cancel()
	if <-done == nil {
		t.Fatal("router ended without cause")
	}
	if _, err = router.Listener("native.synthetic.invalid").Accept(); err == nil {
		t.Fatal("child open after the router ended")
	}
}
