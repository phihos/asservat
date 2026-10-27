//go:build ignore

// provider-proxy is an owned, synthetic integration fixture only. It has no
// product entry point or authority; it bridges TLS to private fixture backends.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "signals" {
		if err := signals(); err != nil {
			fmt.Fprintln(os.Stderr, "synthetic signal workload failed")
			os.Exit(1)
		}
		return
	}
	if err := serve(); err != nil {
		fmt.Fprintln(os.Stderr, "synthetic TLS provider fixture failed")
		os.Exit(1)
	}
}
func serve() error {
	if len(os.Args) != 4 {
		return fmt.Errorf("arguments")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	var ip net.IP
	for _, a := range addresses {
		v, _, e := net.ParseCIDR(a.String())
		if e == nil && v.To4() != nil && v.IsPrivate() && !v.IsLoopback() {
			if ip != nil {
				return fmt.Errorf("multiple networks")
			}
			ip = v
		}
	}
	if ip == nil {
		return fmt.Errorf("private network missing")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return err
	}
	cert := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{ip}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	failures := make(chan error, 3)
	for i, port := range []string{"8443", "8444"} {
		upstream, e := url.Parse(os.Args[i+1])
		if e != nil || upstream.Scheme != "http" || upstream.Host == "" {
			return fmt.Errorf("backend")
		}
		proxy := httputil.NewSingleHostReverseProxy(upstream)
		transport := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 5 * time.Second}
		defer transport.CloseIdleConnections()
		proxy.Transport = transport
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
			http.Error(w, "fixture backend unavailable", http.StatusBadGateway)
		}
		ln, e := tls.Listen("tcp", net.JoinHostPort(ip.String(), port), config)
		if e != nil {
			return e
		}
		server := &http.Server{Handler: proxy, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 32768}
		defer server.Close()
		go func() { failures <- server.Serve(ln) }()
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "8445"))
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				failures <- e
				return
			}
			go postgres(conn, os.Args[3], config)
		}
	}()
	// Public certificate and endpoints only; never log proxy bodies or credentials.
	if err = json.NewEncoder(os.Stdout).Encode(struct {
		S3, KMS, Postgres string
		Root              []byte
	}{"https://" + ip.String() + ":8443", "https://" + ip.String() + ":8444", ip.String() + ":8445", der}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-failures:
		return err
	}
}
func postgres(raw net.Conn, backend string, config *tls.Config) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	var request [8]byte
	if _, err := io.ReadFull(raw, request[:]); err != nil || request != [8]byte{0, 0, 0, 8, 4, 210, 22, 47} {
		return
	}
	if _, err := raw.Write([]byte("S")); err != nil {
		return
	}
	conn := tls.Server(raw, config)
	if conn.Handshake() != nil {
		return
	}
	upstream, err := net.DialTimeout("tcp", backend, time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	_ = raw.SetDeadline(time.Time{})
	joined := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close(); close(joined) }()
	_, _ = io.Copy(conn, upstream)
	_ = conn.Close()
	<-joined
}

// signals is the ADR-241 installed log/resource focus workload: on GET
// /log?line=<text> it writes one synthetic line to stdout; on GET
// /burn?seconds=<n> it keeps one CPU busy for n seconds (at most 300). It
// reads no input besides these parameters and exits on SIGTERM.
func signals() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	mux := http.NewServeMux()
	mux.HandleFunc("/log", func(w http.ResponseWriter, r *http.Request) {
		line := r.URL.Query().Get("line")
		if line == "" || len(line) > 4096 {
			http.Error(w, "line", http.StatusBadRequest)
			return
		}
		fmt.Fprintln(os.Stdout, line)
	})
	mux.HandleFunc("/burn", func(w http.ResponseWriter, r *http.Request) {
		var seconds int
		if _, err := fmt.Sscan(r.URL.Query().Get("seconds"), &seconds); err != nil || seconds < 1 || seconds > 300 {
			http.Error(w, "seconds", http.StatusBadRequest)
			return
		}
		go func() {
			for end := time.Now().Add(time.Duration(seconds) * time.Second); time.Now().Before(end) && ctx.Err() == nil; {
			}
		}()
	})
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = server.Close() }()
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}
