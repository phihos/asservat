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
	"sync"
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
	var mu sync.Mutex
	events := map[string]bool{}
	router.Report = func(e string) { mu.Lock(); events[e] = true; mu.Unlock() }
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
	for until := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		mu.Lock()
		reported := events["unknown-name"] && events["peek-failed"] && events["started"] && events["handoff native.synthetic.invalid"]
		mu.Unlock()
		if reported {
			break
		}
		if time.Now().After(until) {
			t.Fatal("router did not report its drops", events)
		}
	}
	cancel()
	if <-done == nil {
		t.Fatal("router ended without cause")
	}
	if _, err = router.Listener("native.synthetic.invalid").Accept(); err == nil {
		t.Fatal("child open after the router ended")
	}
}

// A child that accepts late makes the router report a slow hand-off.
func TestServerNameRouterReportsSlowHandoff(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router, err := NewServerNameRouter(ctx, raw, "observation.synthetic.invalid")
	if err != nil {
		t.Fatal(err)
	}
	reported := make(chan string, 4)
	router.Report = func(e string) { reported <- e }
	go func() { _ = router.Run() }()
	go func() {
		c, e := tls.Dial("tcp", raw.Addr().String(), &tls.Config{ServerName: "observation.synthetic.invalid", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		if e == nil {
			c.Close()
		}
	}()
	next := func() string {
		for {
			select {
			case e := <-reported:
				if e != "started" {
					return e
				}
			case <-time.After(3 * time.Second):
				t.Fatal("no event")
			}
		}
	}
	// Reported while the hand-off is still blocked, before any Accept.
	if e := next(); e != "slow-handoff observation.synthetic.invalid" {
		t.Fatal("event", e)
	}
	conn, err := router.Listener("observation.synthetic.invalid").Accept()
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if e := next(); e != "late-handoff observation.synthetic.invalid" {
		t.Fatal("event", e)
	}
	// A child that closes while a hand-off waits drops the connection.
	go func() {
		c, e := tls.Dial("tcp", raw.Addr().String(), &tls.Config{ServerName: "observation.synthetic.invalid", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		if e == nil {
			c.Close()
		}
	}()
	if e := next(); e != "slow-handoff observation.synthetic.invalid" {
		t.Fatal("event", e)
	}
	router.Listener("observation.synthetic.invalid").Close()
	if e := next(); e != "dropped-handoff observation.synthetic.invalid" {
		t.Fatal("event", e)
	}
}

// ADR-204 decision 9: one server name split by whether the ClientHello offers
// h2; other names keep their own key and an unkeyed hello closes.
func TestClientHelloRouterSplitsOneNameByProtocol(t *testing.T) {
	const name, exact = "worker.synthetic.invalid", "relay.synthetic.invalid"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{name, exact}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
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
	defer cancel()
	if _, err = NewClientHelloRouter(ctx, raw, nil, name); err == nil {
		t.Fatal("router without a classifier")
	}
	if _, err = NewClientHelloRouter(ctx, raw, func(*tls.ClientHelloInfo) string { return "" }, ""); err == nil {
		t.Fatal("empty key accepted")
	}
	router, err := NewClientHelloRouter(ctx, raw, func(h *tls.ClientHelloInfo) string {
		for _, p := range h.SupportedProtos {
			if h.ServerName == name && p == "h2" {
				return name + "#h2"
			}
		}
		return h.ServerName
	}, exact, name, name+"#h2")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- router.Run() }()
	for _, k := range []string{exact, name, name + "#h2"} {
		child := tls.NewListener(router.Listener(k), &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
		go func() {
			for {
				c, e := child.Accept()
				if e != nil {
					return
				}
				go func() { defer c.Close(); _, _ = c.Write([]byte(k)) }()
			}
		}()
	}
	for _, x := range []struct {
		server string
		protos []string
		want   string
	}{{name, nil, name}, {name, []string{"http/1.1"}, name}, {name, []string{"h2"}, name + "#h2"}, {name, []string{"http/1.1", "h2"}, name + "#h2"}, {exact, []string{"h2"}, exact}, {exact, nil, exact}, {"other.synthetic.invalid", []string{"h2"}, ""}} {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", raw.Addr().String(), &tls.Config{ServerName: x.server, RootCAs: roots, MinVersion: tls.VersionTLS13, NextProtos: x.protos, InsecureSkipVerify: x.want == ""})
		if x.want == "" {
			if err == nil {
				c.Close()
				t.Fatal("unknown key routed")
			}
			continue
		}
		if err != nil {
			t.Fatal(x, err)
		}
		got, _ := io.ReadAll(c)
		c.Close()
		if string(got) != x.want {
			t.Fatalf("%v reached %q", x, got)
		}
	}
	cancel()
	<-done
}
