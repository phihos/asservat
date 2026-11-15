package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/transport/node"
)

type testNodeAttester struct {
	mu      sync.Mutex
	pod     string
	nodeUID string
}

func (a *testNodeAttester) AttestNode(_ context.Context, token []byte) (collector.Identity, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if string(token) != "synthetic.node.token" {
		return collector.Identity{}, delivery.ErrNodeDenied
	}
	nodeUID := a.nodeUID
	if nodeUID == "" {
		nodeUID = "node-uid"
	}
	return collector.Identity{NodeName: "worker-1", NodeUID: nodeUID, PodName: "collector-1", PodUID: a.pod, BootID: "22222222-2222-4222-8222-222222222222", Runtime: "containerd://2.1.3"}, nil
}

// serverCertificate is a synthetic connector server identity for 127.0.0.1.
func serverCertificate(t *testing.T) (tls.Certificate, *x509.CertPool, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic node-channel root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"asservat-connector-nodes"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, _ := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}

func startNodeServer(t *testing.T) (*NodeChannelServer, *testNodeAttester, string, *x509.CertPool, *bytes.Buffer) {
	t.Helper()
	cert, roots, _ := serverCertificate(t)
	att := &testNodeAttester{pod: "pod-1"}
	var out bytes.Buffer
	var mu sync.Mutex
	s, err := NewNodeChannelServer(att, cert, lockedWriter{&mu, &out}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return s, att, "https://" + l.Addr().String(), roots, &out
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

func TestNodeProcessOverTLS(t *testing.T) {
	s, att, endpoint, roots, out := startNodeServer(t)
	token := "synthetic.node.token"
	var mu sync.Mutex
	client, err := node.NewClient(endpoint, "asservat-connector-nodes", roots, func(context.Context) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		return []byte(token), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := collector.Facts{KernelRelease: "6.8.0-1017-azure", Kernel: collector.KernelVersion{Major: 6, Minor: 8, Patch: 0}, BTF: collector.Supported, CgroupV2: collector.Supported, BPF: collector.Denied, TCX: collector.Denied, TC: collector.Denied,
		DebugFS: collector.Unsupported, TraceFS: collector.Unsupported, BPFFS: collector.Unsupported, HostProcesses: collector.Supported, Runtime: collector.RuntimeContainerd}
	budget, _ := collector.NewBudget(collector.Ceilings{RingBytes: 256 << 20, FrozenBytes: 256 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, time.Now())
	var log bytes.Buffer
	p := &nodeProcess{connect: func(ctx context.Context) (nodeStream, error) {
		s, err := client.Connect(ctx, nodeCapabilities)
		if err != nil {
			return nil, err
		}
		return s, nil
	}, podUID: "pod-1", facts: facts, mechanisms: collector.Assess(facts), budget: budget, now: time.Now, sleep: nodeSleep, log: lockedWriter{&mu, &log}}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	wait := func(what string, ok func() bool) {
		t.Helper()
		for n := 0; !ok(); n++ {
			if n > 1000 {
				t.Fatal(what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait("first report", func() bool { v := s.Channel.Nodes(); return len(v) == 1 && v[0].Current })
	if v := s.Channel.Nodes()[0]; v.Report.Facts.KernelRelease != "6.8.0-1017-azure" || v.Report.Mechanisms[0].Adapter != collector.AdapterUnavailable || v.Report.Budget.Ceilings.RingBytes != 256<<20 {
		t.Fatalf("connector view %+v", v)
	}
	// Pushed work is answered with a receipt that removes it from the queue.
	if _, err := s.Channel.Enqueue("node-uid", collector.WorkStopSource, time.Now().Add(time.Minute)); !errors.Is(err, delivery.ErrNodeUnavailable) {
		t.Fatalf("a kind the collector did not announce was queued: %v", err)
	}
	if _, err := s.Channel.Enqueue("node-uid", collector.WorkCancelPacketCapture, time.Now().Add(time.Minute)); !errors.Is(err, delivery.ErrNodeInvalid) {
		t.Fatalf("payload kind without payload: %v", err)
	}
	// A collector Pod on the same node replaces this stream.
	att.mu.Lock()
	att.pod = "pod-2"
	att.mu.Unlock()
	second, _ := node.NewClient(endpoint, "asservat-connector-nodes", roots, func(context.Context) ([]byte, error) { return []byte("synthetic.node.token"), nil })
	stream, err := second.Connect(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if v := s.Channel.Nodes(); len(v) != 1 || v[0].Identity.PodUID != "pod-2" || v[0].Report != nil {
		t.Fatalf("after replacement %+v", v)
	}
	mu.Lock()
	lines := out.String()
	mu.Unlock()
	if !strings.Contains(lines, "connector node worker-1 (uid node-uid) pod collector-1") {
		t.Fatalf("operator lines:\n%s", lines)
	}
	// The client pins the connector name and roots.
	wrong, _ := node.NewClient(endpoint, "other-name", roots, func(context.Context) ([]byte, error) { return []byte("synthetic.node.token"), nil })
	if _, err := wrong.Connect(t.Context(), nil); !errors.Is(err, node.ErrUnavailable) {
		t.Fatalf("server name not pinned: %v", err)
	}
	mu.Lock()
	token = "other.node.token"
	mu.Unlock()
	if _, err := client.Connect(t.Context(), nil); !errors.Is(err, node.ErrRefused) {
		t.Fatalf("denied token: %v", err)
	}
}

func TestNodeDeploymentValidation(t *testing.T) {
	_, _, rootsPEM := serverCertificate(t)
	good := contracts.NodeDeployment{Format: contracts.NodeDeploymentFormat,
		Connector: contracts.NodeConnectorEndpoint{Endpoint: "https://asservat-connector-nodes.asservat-connector.svc:8444", ServerName: "asservat-connector-nodes", RootsPEM: rootsPEM},
		Ceilings:  contracts.NodeCeilings{RingBytes: 256 << 20, FrozenBytes: 256 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}}
	if _, err := validNodeDeployment(good); err != nil {
		t.Fatal(err)
	}
	good.Ceilings.MaxActiveSources = 16
	good.Ceilings.InputBytesPerSecond, good.Ceilings.InputBurstBytes = 16<<20, 16<<20
	if _, err := validNodeDeployment(good); err != nil {
		t.Fatal("complete development source ceilings", err)
	}
	for name, edit := range map[string]func(*contracts.NodeDeployment){
		"format":   func(d *contracts.NodeDeployment) { d.Format = "other" },
		"http":     func(d *contracts.NodeDeployment) { d.Connector.Endpoint = "http://connector:8444" },
		"path":     func(d *contracts.NodeDeployment) { d.Connector.Endpoint = "https://connector:8444/other" },
		"user":     func(d *contracts.NodeDeployment) { d.Connector.Endpoint = "https://u:p@connector:8444" },
		"no name":  func(d *contracts.NodeDeployment) { d.Connector.ServerName = "" },
		"no roots": func(d *contracts.NodeDeployment) { d.Connector.RootsPEM = "" },
		"junk roots": func(d *contracts.NodeDeployment) {
			d.Connector.RootsPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		},
		"ceiling":               func(d *contracts.NodeDeployment) { d.Ceilings.RingBytes = collector.MaxNodeRingBytes + 1 },
		"rate only":             func(d *contracts.NodeDeployment) { d.Ceilings.UploadBurstBytes = 0 },
		"source partial":        func(d *contracts.NodeDeployment) { d.Ceilings.InputBurstBytes = 0 },
		"source count overflow": func(d *contracts.NodeDeployment) { d.Ceilings.MaxActiveSources = collector.MaxActiveSources + 1 },
	} {
		d := good
		edit(&d)
		if _, err := validNodeDeployment(d); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
