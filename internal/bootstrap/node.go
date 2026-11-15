package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/linux"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/transport/node"
)

// ADR-246: the `asservat node` collector process. It probes its node once,
// then holds one stream to its connector, authenticated by its projected
// ServiceAccount token: Hello, status on change, pushed work and receipts.
// It holds no SQL, Kubernetes writer, evidence or key credential.

var errNodeGuard = errors.New("node collector refused: disposable-host guard absent")

// Reconnect backoff: jittered exponential from one second up to 30 seconds.
const (
	nodeRetryMin = time.Second
	nodeRetryMax = 30 * time.Second
)

func readNodeDeployment(ctx context.Context) (contracts.NodeDeployment, *x509.CertPool, error) {
	root, err := os.OpenRoot(contracts.NodeDeploymentRoot)
	if err != nil {
		return contracts.NodeDeployment{}, nil, mounts.ErrUnavailable
	}
	defer root.Close()
	b, err := mounts.Read(ctx, root, contracts.NodeDeploymentFile, contracts.NodeDeploymentMaxBytes)
	if err != nil {
		return contracts.NodeDeployment{}, nil, mounts.ErrUnavailable
	}
	d, err := contracts.DecodeNodeDeployment(bytes.NewReader(b))
	if err != nil {
		return contracts.NodeDeployment{}, nil, mounts.ErrUnavailable
	}
	if d.Connector.RootsPEM == "" {
		// The connector publishes its listener root next to node.json.
		pem, err := mounts.Read(ctx, root, contracts.NodeConnectorRootFile, 16<<10)
		if err != nil {
			return contracts.NodeDeployment{}, nil, mounts.ErrUnavailable
		}
		d.Connector.RootsPEM = string(pem)
	}
	roots, err := validNodeDeployment(d)
	return d, roots, err
}

func validNodeDeployment(d contracts.NodeDeployment) (*x509.CertPool, error) {
	if d.Live != nil && !nodeLiveLimits(*d.Live).Valid() {
		return nil, mounts.ErrUnavailable
	}

	if d.Format != contracts.NodeDeploymentFormat ||
		!node.DomainCeilings(d.Ceilings).Valid() || d.Connector.ServerName == "" || len(d.Connector.ServerName) > 253 {
		return nil, mounts.ErrUnavailable
	}
	u, err := url.Parse(d.Connector.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, mounts.ErrUnavailable
	}
	roots := x509.NewCertPool()
	rest, n := []byte(d.Connector.RootsPEM), 0
	for len(bytes.TrimSpace(rest)) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || n == 8 {
			return nil, mounts.ErrUnavailable
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !c.IsCA {
			return nil, mounts.ErrUnavailable
		}
		roots.AddCert(c)
		n++
	}
	if n == 0 {
		return nil, mounts.ErrUnavailable
	}
	return roots, nil
}

func readNodeToken(ctx context.Context) ([]byte, error) {
	root, err := os.OpenRoot(contracts.NodeTokenRoot)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	defer root.Close()
	b, err := mounts.Read(ctx, root, contracts.NodeTokenFile, contracts.WorkerEnrollmentMaxToken)
	if err != nil || !contracts.ValidWorkerToken(b) {
		clear(b)
		return nil, mounts.ErrUnavailable
	}
	return b, nil
}

// probeNode gathers the node's facts and assessment. The BPF probe loads one
// trivial program; it runs only here, in the privileged collector.
func probeNode() collector.Facts {
	f := linux.NewFileProbe("/").Facts()
	f.BPF, f.TC, f.TCX = linux.ProbeBPF()
	f.Engine = gadget.Initialize(f)
	return f
}

func describeNode(f collector.Facts, mechanisms []collector.Availability) string {
	parts := []string{"kernel " + f.KernelRelease, "btf " + string(f.BTF), "cgroup2 " + string(f.CgroupV2), "bpf " + string(f.BPF), "tcx " + string(f.TCX), "tc " + string(f.TC),
		"tracefs " + string(f.TraceFS), "hostpid " + string(f.HostProcesses), "runtime " + string(f.Runtime), fmt.Sprintf("engine linked=%t initialized=%t %s", f.Engine.Linked, f.Engine.Initialized, f.Engine.Version)}
	for _, m := range mechanisms {
		reasons := make([]string, len(m.Reasons))
		for i, r := range m.Reasons {
			reasons[i] = string(r)
		}
		parts = append(parts, fmt.Sprintf("%s %s prerequisites=%t hook=%q [%s]", m.Mechanism, m.Adapter, m.Prerequisites, m.Hook, strings.Join(reasons, ",")))
	}
	return strings.Join(parts, "; ")
}

func RunNode(ctx context.Context, podUID string) error {
	if st, err := os.Stat(contracts.NodeDisposableHostGuard); err != nil || !st.Mode().IsRegular() {
		return errNodeGuard
	}
	if ctx == nil || !authorization.UUID(podUID) || disableWorkerCoreDumps() != nil {
		return mounts.ErrUnavailable
	}
	d, roots, err := readNodeDeployment(ctx)
	if err != nil {
		return err
	}
	facts := probeNode()
	mechanisms := collector.Assess(facts)
	if gadget.ProfileDialAvailable() && facts.HostProcesses == collector.Supported {
		mechanisms = append(mechanisms, collector.Availability{Mechanism: collector.MechanismProfile, Prerequisites: true, Adapter: collector.AdapterAvailable, ProfileTLS: true, ProfileAuthorization: true})
	}
	// The syscall recorder decodes x86_64 numbers only (ADR-273).
	if runtime.GOARCH != "amd64" {
		for i := range mechanisms {
			if mechanisms[i].Mechanism == collector.MechanismSyscall && mechanisms[i].Adapter == collector.AdapterAvailable {
				mechanisms[i].Adapter, mechanisms[i].Reasons = collector.AdapterUnavailable, append(mechanisms[i].Reasons, collector.ReasonRecorderNotImplemented)
			}
		}
	}
	fmt.Fprintln(os.Stderr, "node collector probe: "+describeNode(facts, mechanisms))
	budget, err := collector.NewBudget(node.DomainCeilings(d.Ceilings), time.Now())
	if err != nil {
		return mounts.ErrUnavailable
	}
	client, err := node.NewClient(d.Connector.Endpoint, d.Connector.ServerName, roots, readNodeToken)
	if err != nil {
		return mounts.ErrUnavailable
	}
	p := &nodeProcess{connect: func(ctx context.Context) (nodeStream, error) {
		s, err := client.Connect(ctx, nodeCapabilities)
		if err != nil {
			return nil, err
		}
		return s, nil
	}, uploadLive: client.UploadLive, podUID: podUID, facts: facts, mechanisms: mechanisms, budget: budget, now: time.Now, sleep: nodeSleep, log: os.Stderr}
	p.packets = &nodePackets{engine: gadget.CapturePackets, syscallTrace: syscallTraceIfAvailable(mechanisms), argumentTrace: argumentTraceIfAvailable(mechanisms), argumentResources: gadget.ArgumentWorkingBytes, observedEngine: gadget.CaptureObservedPackets, upload: client.UploadCapture, available: packetAvailable(mechanisms), version: facts.Engine.Version,
		now: time.Now, log: func(line string) { fmt.Fprintln(os.Stderr, line) }, budget: func() *collector.Budget { return p.budget }, budgetMu: &p.mu}
	p.profiles = &nodeProfiles{acquire: acquireNodeProfile(time.Now), upload: client.UploadProfileStream, now: time.Now, budget: func() *collector.Budget { return p.budget }, budgetMu: &p.mu}
	ringDir, removed := "", 0
	if st, err := os.Stat(contracts.NodeRingDiskPath); err == nil && st.IsDir() && d.Ceilings.RingDiskBytes > 0 {
		ringDir = contracts.NodeRingDiskPath
		// The volume outlives container restarts; earlier processes' sealed
		// segments are unreadable without their keys, so remove them.
		if entries, err := os.ReadDir(ringDir); err == nil {
			for _, e := range entries {
				if os.RemoveAll(filepath.Join(ringDir, e.Name())) == nil {
					removed++
				}
			}
		}
	}
	fmt.Fprintf(os.Stderr, "node collector ring medium: encrypted disk available=%t removedEarlier=%d\n", ringDir != "", removed)
	p.sources = &nodeSources{ringDir: ringDir, ringDiskBytes: d.Ceilings.RingDiskBytes, log: p.packets.log, upload: client.UploadCapture, takeUpload: p.packets.takeUpload, version: facts.Engine.Version, engine: gadget.CaptureObservedPackets, syscallEngine: syscallTraceIfAvailable(mechanisms), now: time.Now, budget: budget, budgetMu: &p.mu, available: packetAvailable(mechanisms)}
	if d.Live != nil {
		p.sources.liveBudget = &nodeLiveBudget{limits: nodeLiveLimits(*d.Live)}
		for n, m := range p.mechanisms {
			if m.Adapter == collector.AdapterAvailable && m.Prerequisites {
				switch m.Mechanism {
				case collector.MechanismPacket:
					p.mechanisms[n].LiveProjections = []string{v.Packet, v.HTTP}
				case collector.MechanismSyscall:
					p.mechanisms[n].LiveProjections = []string{v.Syscall}
				}
			}
		}
	}
	err = p.Run(ctx)
	p.sources.Close()
	p.packets.wg.Wait()
	p.profiles.wg.Wait()
	return err
}

func packetAvailable(m []collector.Availability) bool {
	return mechanismAvailable(m, collector.MechanismPacket)
}

func mechanismAvailable(m []collector.Availability, mechanism collector.Mechanism) bool {
	for _, a := range m {
		if a.Mechanism == mechanism {
			return a.Adapter == collector.AdapterAvailable
		}
	}
	return false
}

// syscallTraceIfAvailable is the syscall engine when this node's assessment
// offers the recorder, else nil (sources then report EngineUnavailable).
func syscallTraceIfAvailable(m []collector.Availability) syscallTraceEngine {
	if !mechanismAvailable(m, collector.MechanismSyscall) {
		return nil
	}
	return gadget.TraceSyscalls
}

func nodeSleep(ctx context.Context, d time.Duration, kick <-chan struct{}) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
	case <-kick:
	}
	return nil
}

// nodeCapabilities are the work kinds this build handles; Hello announces them.
var nodeCapabilities = []collector.WorkKind{collector.WorkLiveRead, collector.WorkProfileCapture, collector.WorkCancelProfileCapture, collector.WorkPacketCapture,
	collector.WorkSyscallCapture, collector.WorkCancelPacketCapture, collector.WorkPacketSource, collector.WorkStopPacketSource, collector.WorkPacketSourceSnapshot, collector.WorkCancelSourceSnapshot}

type nodeStream interface {
	Status(collector.Report) error
	Receive() (delivery.NodeWorkDelivery, error)
	Close()
}

// nodeProcess is one collector process.
type nodeProcess struct {
	connect    func(context.Context) (nodeStream, error)
	uploadLive func(context.Context, v.NodeReply) error
	podUID     string // validated startup input, never chosen by a work item
	facts      collector.Facts
	mechanisms []collector.Availability
	now        func() time.Time
	sleep      func(context.Context, time.Duration, <-chan struct{}) error
	log        io.Writer
	// packets runs packet captures (ADR-248); nil refuses every item.
	packets  *nodePackets
	profiles *nodeProfiles
	sources  *nodeSources
	// root is the process context: captures outlive a reconnect.
	root context.Context

	mu       sync.Mutex
	budget   *collector.Budget
	receipts []collector.Receipt
	last     string
}

func (p *nodeProcess) note(cause string) {
	p.mu.Lock()
	changed := cause != p.last
	p.last = cause
	p.mu.Unlock()
	if changed && cause != "" {
		fmt.Fprintln(p.log, "node collector: "+cause)
	}
}

func channelCause(err error) string {
	switch {
	case errors.Is(err, node.ErrRefused):
		return "connector refused the stream"
	case errors.Is(err, node.ErrUnavailable):
		return "connector unavailable"
	}
	return "unavailable"
}

func (p *nodeProcess) report() collector.Report {
	var sources []collector.SourceStatus
	var sourceAsOf time.Time
	var live *collector.LiveStatus
	if p.sources != nil {
		live = p.sources.liveStatus()
		sources, sourceAsOf = p.sources.Status()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.receipts)
	if n > collector.MaxReceipts {
		n = collector.MaxReceipts
	}
	now := p.now()
	if !sourceAsOf.IsZero() {
		now = sourceAsOf
	}
	if live != nil && live.WindowStartedAt.After(now) {
		now = live.WindowStartedAt
	}
	return collector.Report{ObservedAt: now.UTC(), Facts: p.facts, Mechanisms: p.mechanisms, Budget: p.budget.Usage(now), Receipts: append([]collector.Receipt{}, p.receipts[:n]...), Sources: sources, Live: live}
}

// statusLoop sends a report after Hello, after each receipt and when the
// report changed. Source counters change with every packet and have no event,
// so a change check runs every StatusInterval; an unchanged report is not
// sent.
func (p *nodeProcess) statusLoop(ctx context.Context, stream nodeStream, kick <-chan struct{}) error {
	tick := time.NewTicker(collector.StatusInterval)
	defer tick.Stop()
	var last []byte
	for {
		r := p.report()
		if key := statusKey(r); len(r.Receipts) > 0 || !bytes.Equal(key, last) {
			if err := stream.Status(r); err != nil {
				return err
			}
			last = key
			p.mu.Lock()
			p.receipts = p.receipts[len(r.Receipts):]
			more := len(p.receipts) > 0
			p.mu.Unlock()
			if more {
				continue
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-kick:
		case <-tick.C:
		}
	}
}

// statusKey is a report without its time, receipts and the continuously
// refilling upload budget.
func statusKey(r collector.Report) []byte {
	w := node.WireStatus(r)
	w.ObservedAt, w.Receipts, w.Budget.UploadAvailable = time.Time{}, nil, 0
	b, _ := json.Marshal(w)
	return b
}

// handle decides one pushed work item and returns its receipt.
func (p *nodeProcess) handle(ctx context.Context, received delivery.NodeWorkDelivery) collector.Receipt {
	w := received.Work
	root := p.root
	if root == nil {
		root = ctx
	}
	// Starting a capture takes the lock for the budget, so decide
	// without holding it.
	r := collector.Decide(w, p.now())
	if p.uploadLive != nil && w.Kind == collector.WorkLiveRead && p.sources != nil && p.sources.liveBudget != nil && w.Live != nil && r.Reason != collector.ReasonWorkUnknown && r.Reason != collector.ReasonWorkExpired {
		// One finite task; registration and the closed check share the lifecycle
		// lock so shutdown joins every task before dropping source/transport state.
		p.sources.mu.Lock()
		if !p.sources.closed {
			p.sources.liveWG.Add(1)
			go func(w collector.Work) {
				defer p.sources.liveWG.Done()
				call, cancel := context.WithDeadline(ctx, w.NotAfter)
				defer cancel()
				var reply v.NodeReply
				var e error
				if w.Live.Manual != nil && p.packets != nil {
					reply, e = p.packets.readManualLive(call, w, p.sources.liveBudget)
				} else {
					reply, e = p.sources.readLive(call, w)
				}
				if e == nil && p.takeLiveUpload(reply) {
					_ = p.uploadLive(call, reply)
				}
				clear(reply.Rows)
			}(w)
			r.Outcome, r.Reason = collector.OutcomeAccepted, ""
		}
		p.sources.mu.Unlock()
	}
	switch {
	case w.Kind == collector.WorkProfileCapture && p.profiles != nil:
		r = p.profiles.start(root, w, received.ProfileAuthorization, received.ProfileAuthorizationUnavailable)
	case w.Kind == collector.WorkCancelProfileCapture && p.profiles != nil:
		r = p.profiles.stop(w)
	case w.Kind == collector.WorkPacketCapture && p.packets != nil:
		r = p.packets.start(root, w)
	case w.Kind == collector.WorkSyscallCapture && p.packets != nil:
		r = p.packets.startSyscall(root, w)
	case w.Kind == collector.WorkCancelPacketCapture && p.packets != nil:
		r = p.packets.cancel(w)
	case (w.Kind == collector.WorkPacketSource || w.Kind == collector.WorkStopPacketSource || w.Kind == collector.WorkPacketSourceSnapshot || w.Kind == collector.WorkCancelSourceSnapshot) && p.sources != nil:
		r = p.sources.decide(root, w)
	}
	return r
}

// session runs one stream until it ends. It reports whether the stream
// opened.
func (p *nodeProcess) session(ctx context.Context) (bool, error) {
	stream, err := p.connect(ctx)
	if err != nil {
		return false, err
	}
	p.note("")
	fmt.Fprintln(p.log, "node collector connected")
	session, cancel := context.WithCancel(ctx)
	kick := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { done <- p.statusLoop(session, stream, kick) }()
	go func() {
		<-session.Done()
		stream.Close()
	}()
	for {
		received, err := stream.Receive()
		if err == nil {
			r := p.handle(session, received)
			clear(received.ProfileAuthorization)
			p.mu.Lock()
			p.receipts = append(p.receipts, r)
			p.mu.Unlock()
			select {
			case kick <- struct{}{}:
			default:
			}
			continue
		}
		cancel()
		if status := <-done; status != nil && !errors.Is(status, context.Canceled) {
			err = status
		}
		return true, err
	}
}

// Run holds the stream until ctx ends, reconnecting with jittered exponential
// backoff. A connector restart only drops the stream.
func (p *nodeProcess) Run(ctx context.Context) error {
	p.root = ctx
	backoff := nodeRetryMin
	for {
		opened, err := p.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if opened {
			backoff = nodeRetryMin
		}
		p.note("stream pending: " + channelCause(err))
		if p.sleep(ctx, backoff/2+rand.N(backoff/2+1), nil) != nil {
			return nil
		}
		backoff = min(2*backoff, nodeRetryMax)
	}
}

// NodeDiagnostic is the collector's single stop line: a fixed cause only.
func NodeDiagnostic(err error) string {
	if errors.Is(err, errNodeGuard) {
		return err.Error() + " (" + contracts.NodeDisposableHostGuard + "); the collector runs only on disposable test hosts until it is qualified"
	}
	return "node collector stopped: protected node input unavailable"
}

func nodeLiveLimits(p contracts.NodeLiveProcessing) v.ProcessingLimits {
	return v.ProcessingLimits{Subscriptions: p.Subscriptions, MemoryBytes: p.MemoryBytes, EventsPerSecond: p.EventsPerSecond, BytesPerSecond: p.BytesPerSecond, TimePerSecond: time.Duration(p.ProcessingNanosPerSecond)}
}
