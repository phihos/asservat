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
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/transport/node"
)

const (
	testNodeBoot  = "22222222-2222-4222-8222-222222222222"
	testNodeEpoch = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

type testNodeAttester struct {
	mu  sync.Mutex
	pod string
}

func (a *testNodeAttester) PrecheckNode([]byte) error { return nil }

func (a *testNodeAttester) AttestNode(_ context.Context, token []byte, boot string) (collector.Identity, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if string(token) != "synthetic.node.token" {
		return collector.Identity{}, delivery.ErrNodeDenied
	}
	return collector.Identity{NodeName: "worker-1", NodeUID: "node-uid", PodName: "collector-1", PodUID: a.pod, BootID: boot, Runtime: "containerd://2.1.3"}, nil
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
	s, err := NewNodeChannelServer("50000000-0000-4000-8000-000000000001", att, cert, lockedWriter{&mu, &out}, time.Now)
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

func TestNodeChannelOverTLS(t *testing.T) {
	s, att, endpoint, roots, out := startNodeServer(t)
	creds, err := mtls.NewNodeCredentials()
	if err != nil {
		t.Fatal(err)
	}
	client, err := node.NewClient(endpoint, "asservat-connector-nodes", roots, creds.GetClientCertificate)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.Poll(ctx, testNodeEpoch, 0); !errors.Is(err, node.ErrUnauthenticated) {
		t.Fatalf("poll before enrollment: %v", err)
	}
	if _, err := client.Enroll(ctx, contracts.NodeEnrollRequest{Token: "other.node.token", CSR: creds.CSR(), BootID: testNodeBoot, Epoch: testNodeEpoch}); !errors.Is(err, node.ErrRefused) {
		t.Fatalf("denied token: %v", err)
	}
	resp, err := client.Enroll(ctx, contracts.NodeEnrollRequest{Token: "synthetic.node.token", CSR: creds.CSR(), BootID: testNodeBoot, Epoch: testNodeEpoch})
	if err != nil || resp.NodeName != "worker-1" || resp.NodeUID != "node-uid" {
		t.Fatalf("enroll: %+v %v", resp, err)
	}
	leaf, _ := x509.ParseCertificate(resp.Certificate)
	if len(leaf.URIs) != 1 || !strings.HasSuffix(leaf.URIs[0].String(), ":node-uid:pod-1:"+testNodeEpoch) || len(leaf.DNSNames) != 0 || leaf.NotAfter.Sub(leaf.NotBefore) > collector.CertificateLifetime+2*time.Minute {
		t.Fatalf("leaf %v %v", leaf.URIs, leaf.NotAfter.Sub(leaf.NotBefore))
	}
	if _, err := creds.Install(resp.Certificate, time.Now()); err != nil {
		t.Fatal(err)
	}
	client.CloseIdle()
	facts := collector.Facts{KernelRelease: "6.8.0-1017-azure", Kernel: collector.KernelVersion{Major: 6, Minor: 8, Patch: 0}, BTF: collector.Supported, CgroupV2: collector.Supported, BPF: collector.Denied, TCX: collector.Denied, TC: collector.Denied,
		DebugFS: collector.Unsupported, TraceFS: collector.Unsupported, BPFFS: collector.Unsupported, HostProcesses: collector.Supported, Runtime: collector.RuntimeContainerd}
	budget, _ := collector.NewBudget(collector.Ceilings{RingBytes: 256 << 20, FrozenBytes: 256 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, time.Now())
	r := collector.Report{Sequence: 1, ObservedAt: time.Now(), Facts: facts, Mechanisms: collector.Assess(facts), Budget: budget.Usage(time.Now())}
	if err := client.Status(ctx, testNodeEpoch, r); err != nil {
		t.Fatal(err)
	}
	views := s.Channel.Nodes()
	if len(views) != 1 || views[0].Report == nil || views[0].Report.Facts.KernelRelease != "6.8.0-1017-azure" || views[0].Report.Mechanisms[0].Adapter != collector.AdapterUnavailable || views[0].Report.Budget.Ceilings.RingBytes != 256<<20 {
		t.Fatalf("connector view %+v", views)
	}
	r.Sequence = 2
	if err := client.Status(ctx, testNodeEpoch, r); err == nil {
		t.Fatal("a report within the minimum spacing was accepted")
	}
	// Long poll: queued work wakes it; the node's receipt removes the item.
	got := make(chan []collector.Work, 1)
	go func() { w, _ := client.Poll(ctx, testNodeEpoch, 0); got <- w }()
	time.Sleep(100 * time.Millisecond)
	w, err := s.Channel.Enqueue("node-uid", collector.WorkArmSource, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case work := <-got:
		if len(work) != 1 || work[0].ID != w.ID || work[0].Kind != collector.WorkArmSource {
			t.Fatalf("polled %+v", work)
		}
		time.Sleep(collector.StatusMinimumSpacing)
		r.Sequence = 3
		r.Receipts = []collector.Receipt{collector.Decide(work[0], time.Now())}
		if err := client.Status(ctx, testNodeEpoch, r); err != nil || s.Channel.Nodes()[0].Queued != 0 {
			t.Fatalf("receipt: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("poll not woken")
	}
	// A restarted collector (new Pod, new epoch) replaces this process.
	att.mu.Lock()
	att.pod = "pod-2"
	att.mu.Unlock()
	next, _ := mtls.NewNodeCredentials()
	second, _ := node.NewClient(endpoint, "asservat-connector-nodes", roots, next.GetClientCertificate)
	resp, err = second.Enroll(ctx, contracts.NodeEnrollRequest{Token: "synthetic.node.token", CSR: next.CSR(), BootID: testNodeBoot, Epoch: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(collector.StatusMinimumSpacing)
	r.Sequence = 4
	if err := client.Status(ctx, testNodeEpoch, r); !errors.Is(err, node.ErrUnauthenticated) {
		t.Fatalf("replaced process still reports: %v", err)
	}
	if v := s.Channel.Nodes(); len(v) != 1 || v[0].Identity.PodUID != "pod-2" || v[0].Report != nil {
		t.Fatalf("after restart %+v", v)
	}
	if !strings.Contains(out.String(), "connector node worker-1 (uid node-uid) pod collector-1 epoch "+testNodeEpoch) || !strings.Contains(out.String(), "packetCapture AdapterUnavailable [BPFUnavailable,") {
		t.Fatalf("operator lines:\n%s", out.String())
	}
	// The client pins the connector name and roots.
	wrong, _ := node.NewClient(endpoint, "other-name", roots, creds.GetClientCertificate)
	if _, err := wrong.Poll(ctx, testNodeEpoch, 0); !errors.Is(err, node.ErrUnavailable) {
		t.Fatalf("server name not pinned: %v", err)
	}
}

// fakeNodeChannel records reports against a fake clock.
type fakeNodeChannel struct {
	mu       sync.Mutex
	clock    *fakeClock
	enrolls  int
	reports  []collector.Report
	at       []time.Time
	unauth   int
	stopAt   int
	cancel   context.CancelFunc
	pollWork []collector.Work
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) sleep(ctx context.Context, d time.Duration, _ <-chan struct{}) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
	return nil
}

func (f *fakeNodeChannel) Enroll(context.Context, contracts.NodeEnrollRequest) (contracts.NodeEnrollResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrolls++
	return contracts.NodeEnrollResponse{NodeName: "worker-1", Certificate: []byte{1}}, nil
}
func (f *fakeNodeChannel) Poll(ctx context.Context, _ string, after uint64) ([]collector.Work, error) {
	f.mu.Lock()
	if len(f.pollWork) > 0 {
		w := f.pollWork
		f.pollWork = nil
		f.mu.Unlock()
		return w, nil
	}
	f.mu.Unlock()
	<-ctx.Done()
	return nil, node.ErrUnavailable
}
func (f *fakeNodeChannel) Status(ctx context.Context, _ string, r collector.Report) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unauth > 0 {
		f.unauth--
		return node.ErrUnauthenticated
	}
	f.reports = append(f.reports, r)
	f.at = append(f.at, f.clock.now())
	if len(f.reports) == f.stopAt {
		f.cancel()
	}
	return nil
}
func (f *fakeNodeChannel) CloseIdle() {}

type fakeNodeKey struct{ clock *fakeClock }

func (fakeNodeKey) CSR() []byte { return []byte("csr") }
func (k fakeNodeKey) Install([]byte, time.Time) (time.Time, error) {
	return k.clock.now().Add(collector.CertificateLifetime), nil
}

func testNodeProcess(ch *fakeNodeChannel, clock *fakeClock) *nodeProcess {
	b, _ := collector.NewBudget(collector.Ceilings{RingBytes: 1 << 20}, clock.now())
	return &nodeProcess{client: ch, creds: fakeNodeKey{clock}, token: func(context.Context) ([]byte, error) { return []byte("synthetic.node.token"), nil },
		bootID: testNodeBoot, epoch: testNodeEpoch, facts: collector.Facts{}, mechanisms: collector.Assess(collector.Facts{}), budget: b, now: clock.now, sleep: clock.sleep, log: &bytes.Buffer{}}
}

func TestNodeStatusCadenceIsFifteenSeconds(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	ctx, cancel := context.WithCancel(context.Background())
	ch := &fakeNodeChannel{clock: clock, stopAt: 5, cancel: cancel}
	p := testNodeProcess(ch, clock)
	if err := p.statusLoop(ctx, make(chan struct{})); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(ch.at) != 5 {
		t.Fatalf("%d reports", len(ch.at))
	}
	for i := range ch.at {
		if ch.reports[i].Sequence != uint64(i+1) || !ch.at[i].Equal(clock.t.Add(-time.Duration(4-i)*collector.StatusInterval)) {
			t.Fatalf("report %d at %v seq %d", i, ch.at[i], ch.reports[i].Sequence)
		}
		if ch.reports[i].Budget.Ceilings.RingBytes != 1<<20 {
			t.Fatal("budget missing from report")
		}
	}
}

func TestNodeReceiptsReportedPromptly(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	ctx, cancel := context.WithCancel(context.Background())
	ch := &fakeNodeChannel{clock: clock, stopAt: 2, cancel: cancel, pollWork: []collector.Work{{ID: "w1", Sequence: 7, Kind: collector.WorkSnapshot, NotAfter: clock.now().Add(time.Hour)}}}
	p := testNodeProcess(ch, clock)
	p.cadence.Sent(clock.now()) // a report was just sent
	kick := make(chan struct{}, 1)
	pollDone := make(chan error, 1)
	go func() { pollDone <- p.pollLoop(ctx, kick) }()
	// Wait until the poll loop has turned the item into a receipt.
	for i := 0; ; i++ {
		p.mu.Lock()
		n := len(p.receipts)
		p.mu.Unlock()
		if n == 1 {
			break
		}
		if i > 1000 {
			t.Fatal("no receipt")
		}
		time.Sleep(time.Millisecond)
	}
	start := clock.now()
	ch.stopAt = 1
	p.statusLoop(ctx, kick)
	<-pollDone
	if len(ch.reports) != 1 || len(ch.reports[0].Receipts) != 1 || ch.reports[0].Receipts[0].Reason != collector.ReasonRecorderNotImplemented || ch.reports[0].Receipts[0].Sequence != 7 {
		t.Fatalf("receipt report %+v", ch.reports)
	}
	if d := ch.at[0].Sub(start); d != collector.StatusMinimumSpacing {
		t.Fatalf("urgent report after %v, want the minimum spacing", d)
	}
	if len(p.receipts) != 0 {
		t.Fatal("sent receipts kept")
	}
}

func TestNodeReenrollsWhenConnectorForgetsIt(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	ctx, cancel := context.WithCancel(context.Background())
	ch := &fakeNodeChannel{clock: clock, unauth: 1, stopAt: 1, cancel: cancel}
	p := testNodeProcess(ch, clock)
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("did not re-enroll")
	}
	if ch.enrolls < 2 || len(ch.reports) != 1 || ch.reports[0].Sequence != 2 {
		t.Fatalf("enrolls %d reports %+v", ch.enrolls, ch.reports)
	}
	if p.epoch != testNodeEpoch {
		t.Fatal("re-enrollment changed the process epoch")
	}
}

func TestNodeDeploymentValidation(t *testing.T) {
	_, _, rootsPEM := serverCertificate(t)
	good := contracts.NodeDeployment{Format: contracts.NodeDeploymentFormat, InstallationID: "10000000-0000-4000-8000-000000000001", ClusterID: "50000000-0000-4000-8000-000000000001",
		Connector: contracts.NodeConnectorEndpoint{Endpoint: "https://asservat-connector-nodes.asservat-connector.svc:8444", ServerName: "asservat-connector-nodes", RootsPEM: rootsPEM},
		Ceilings:  contracts.NodeCeilings{RingBytes: 256 << 20, FrozenBytes: 256 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}}
	if _, err := validNodeDeployment(good); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*contracts.NodeDeployment){
		"format":       func(d *contracts.NodeDeployment) { d.Format = "other" },
		"installation": func(d *contracts.NodeDeployment) { d.InstallationID = "x" },
		"http":         func(d *contracts.NodeDeployment) { d.Connector.Endpoint = "http://connector:8444" },
		"path":         func(d *contracts.NodeDeployment) { d.Connector.Endpoint = "https://connector:8444/other" },
		"user":         func(d *contracts.NodeDeployment) { d.Connector.Endpoint = "https://u:p@connector:8444" },
		"no name":      func(d *contracts.NodeDeployment) { d.Connector.ServerName = "" },
		"no roots":     func(d *contracts.NodeDeployment) { d.Connector.RootsPEM = "" },
		"junk roots": func(d *contracts.NodeDeployment) {
			d.Connector.RootsPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		},
		"ceiling":   func(d *contracts.NodeDeployment) { d.Ceilings.RingBytes = collector.MaxNodeRingBytes + 1 },
		"rate only": func(d *contracts.NodeDeployment) { d.Ceilings.UploadBurstBytes = 0 },
	} {
		d := good
		edit(&d)
		if _, err := validNodeDeployment(d); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// sequencedChannel serves queued work like the connector: every item after
// the cursor, at most 16 per poll, until it is answered.
type sequencedChannel struct {
	fakeNodeChannel
	queue  []collector.Work
	afters []uint64
}

func (f *sequencedChannel) Poll(ctx context.Context, _ string, after uint64) ([]collector.Work, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.afters = append(f.afters, after)
	if len(f.afters) > 40 {
		f.cancel()
		return nil, node.ErrUnavailable
	}
	var out []collector.Work
	for _, w := range f.queue {
		if w.Sequence > after && len(out) < collector.MaxWorkPerPoll {
			out = append(out, w)
		}
	}
	return out, nil
}

func TestNodeReceiptBufferNeverSkipsQueuedWork(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	ctx, cancel := context.WithCancel(context.Background())
	ch := &sequencedChannel{fakeNodeChannel: fakeNodeChannel{clock: clock, cancel: cancel}}
	for i := 1; i <= nodeReceiptBuffer+40; i++ {
		ch.queue = append(ch.queue, collector.Work{ID: fmt.Sprintf("w%d", i), Sequence: uint64(i), Kind: collector.WorkSnapshot, NotAfter: clock.now().Add(time.Hour)})
	}
	p := testNodeProcess(&ch.fakeNodeChannel, clock)
	p.client = ch
	// While the buffer is full the loop only waits; end the test after a few waits.
	waits := 0
	p.sleep = func(ctx context.Context, d time.Duration, k <-chan struct{}) error {
		if waits++; waits > 3 {
			ch.mu.Lock()
			ch.cancel()
			ch.mu.Unlock()
		}
		return clock.sleep(ctx, d, k)
	}
	kick := make(chan struct{}, 1)
	// No status loop runs: the buffer fills and polling must stop there.
	if err := p.pollLoop(ctx, kick); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(p.receipts) != nodeReceiptBuffer {
		t.Fatalf("buffered %d receipts", len(p.receipts))
	}
	for i, r := range p.receipts {
		if r.Sequence != uint64(i+1) {
			t.Fatalf("receipt %d has sequence %d: an item was skipped", i, r.Sequence)
		}
	}
	// The last poll filled the buffer; none followed while it stayed full.
	if last := ch.afters[len(ch.afters)-1]; last != uint64(nodeReceiptBuffer-collector.MaxWorkPerPoll) {
		t.Fatalf("polled with cursor %d while the buffer was full", last)
	}
	// The receipts are reported and the connector drops the answered items;
	// polling continues with the first unanswered one.
	p.mu.Lock()
	p.receipts = nil
	p.mu.Unlock()
	ch.queue = ch.queue[nodeReceiptBuffer:]
	ctx, cancel = context.WithCancel(context.Background())
	ch.cancel, ch.afters, waits = cancel, nil, -1000
	p.pollLoop(ctx, kick)
	if p.receipts[0].Sequence != uint64(nodeReceiptBuffer+1) || len(p.receipts) != 40 {
		t.Fatalf("resumed at %d with %d receipts", p.receipts[0].Sequence, len(p.receipts))
	}
}
