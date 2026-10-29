package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/linux"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/transport/node"
	"github.com/google/uuid"
)

// ADR-246: the `asservat node` collector process. It probes its node once,
// enrolls with the connector through its Pod-bound projected token and a
// process-owned key, then reports status every 15 seconds and long-polls for
// work until it stops. It holds no SQL, Kubernetes writer, evidence or key
// credential, and in this increment records nothing.

var errNodeGuard = errors.New("node collector refused: disposable-host guard absent")

const nodeRetry = 5 * time.Second

// nodeReceiptBuffer bounds receipts not yet reported: four full reports.
const nodeReceiptBuffer = 4 * collector.MaxReceipts

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
	roots, err := validNodeDeployment(d)
	return d, roots, err
}

func validNodeDeployment(d contracts.NodeDeployment) (*x509.CertPool, error) {
	if d.Format != contracts.NodeDeploymentFormat || !authorization.UUID(d.InstallationID) || !authorization.UUID(d.ClusterID) ||
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
	probe := linux.NewFileProbe("/")
	boot, err := probe.BootID()
	if err != nil || !authorization.UUID(boot) {
		return mounts.ErrUnavailable
	}
	facts := probeNode()
	mechanisms := collector.Assess(facts)
	fmt.Fprintln(os.Stderr, "node collector probe: "+describeNode(facts, mechanisms))
	budget, err := collector.NewBudget(node.DomainCeilings(d.Ceilings), time.Now())
	if err != nil {
		return mounts.ErrUnavailable
	}
	creds, err := mtls.NewNodeCredentials()
	if err != nil {
		return err
	}
	client, err := node.NewClient(d.Connector.Endpoint, d.Connector.ServerName, roots, creds.GetClientCertificate)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer client.CloseIdle()
	p := &nodeProcess{client: client, creds: creds, token: readNodeToken, podUID: podUID, bootID: boot, epoch: uuid.NewString(), facts: facts, mechanisms: mechanisms,
		budget: budget, now: time.Now, sleep: nodeSleep, log: os.Stderr}
	p.packets = &nodePackets{engine: gadget.CapturePackets, observedEngine: gadget.CaptureObservedPackets, identity: p.packetIdentity, upload: client.UploadCapture, available: packetAvailable(mechanisms), version: facts.Engine.Version,
		now: time.Now, log: func(line string) { fmt.Fprintln(os.Stderr, line) }, budget: func() *collector.Budget { return p.budget }, budgetMu: &p.mu}
	p.sources = &nodeSources{engine: gadget.CaptureObservedPackets, identity: p.packetIdentity, now: time.Now, budget: budget, budgetMu: &p.mu, available: packetAvailable(mechanisms)}
	err = p.Run(ctx)
	p.sources.Close()
	p.packets.wg.Wait()
	return err
}

func packetAvailable(m []collector.Availability) bool {
	for _, a := range m {
		if a.Mechanism == collector.MechanismPacket {
			return a.Adapter == collector.AdapterAvailable
		}
	}
	return false
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

type nodeChannel interface {
	Enroll(context.Context, contracts.NodeEnrollRequest) (contracts.NodeEnrollResponse, error)
	Poll(ctx context.Context, epoch string, after uint64) ([]collector.Work, error)
	Status(ctx context.Context, epoch string, r collector.Report) error
	UploadCapture(ctx context.Context, epoch string, r collector.PacketResult, pcapng []byte) error
	CloseIdle()
}

type nodeKey interface {
	CSR() []byte
	Install(der []byte, now time.Time) (time.Time, error)
}

// nodeProcess is one collector generation: its epoch never changes, and a
// process restart is the only way to obtain a new one.
type nodeProcess struct {
	client     nodeChannel
	creds      nodeKey
	token      func(context.Context) ([]byte, error)
	bootID     string
	podUID     string // validated startup input, never chosen by a work item
	nodeUID    string // last successful authenticated enrollment response
	epoch      string
	facts      collector.Facts
	mechanisms []collector.Availability
	now        func() time.Time
	sleep      func(context.Context, time.Duration, <-chan struct{}) error
	log        io.Writer
	// packets runs packet captures (ADR-248); nil refuses every item.
	packets *nodePackets
	sources *nodeSources
	// root is the process context: captures outlive a re-enrollment.
	root context.Context

	mu       sync.Mutex
	budget   *collector.Budget
	receipts []collector.Receipt
	sequence uint64
	cadence  collector.StatusCadence
	last     string
}

func (p *nodeProcess) packetIdentity() collector.Identity {
	p.mu.Lock()
	defer p.mu.Unlock()
	return collector.Identity{NodeUID: p.nodeUID, PodUID: p.podUID, BootID: p.bootID, Epoch: p.epoch}
}

var errNodeReenroll = errors.New("node channel: enroll again")

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
	case errors.Is(err, node.ErrUnauthenticated):
		return "connector no longer knows this process; enrolling again"
	case errors.Is(err, node.ErrRefused):
		return "connector refused the request"
	case errors.Is(err, node.ErrUnavailable):
		return "connector unavailable"
	case errors.Is(err, mounts.ErrUnavailable):
		return "projected token unavailable"
	}
	return "unavailable"
}

// enroll obtains a certificate for this process's key, retrying every five
// seconds. Renewal is the same request with the same key and epoch.
func (p *nodeProcess) enroll(ctx context.Context) (time.Time, error) {
	for {
		token, err := p.token(ctx)
		if err == nil {
			var resp contracts.NodeEnrollResponse
			resp, err = p.client.Enroll(ctx, contracts.NodeEnrollRequest{Token: string(token), CSR: p.creds.CSR(), BootID: p.bootID, Epoch: p.epoch})
			clear(token)
			if err == nil {
				var notAfter time.Time
				// Certificate installation is local crypto. Keep it and its
				// authenticated source identity atomic to packet start snapshots.
				p.mu.Lock()
				notAfter, err = p.creds.Install(resp.Certificate, p.now())
				if err == nil {
					p.nodeUID = resp.NodeUID
				}
				p.mu.Unlock()
				if err == nil {
					p.client.CloseIdle()
					p.note("")
					fmt.Fprintf(p.log, "node collector enrolled: node %s, epoch %s, certificate until %s\n", resp.NodeName, p.epoch, notAfter.UTC().Format(time.RFC3339))
					return notAfter, nil
				}
			}
		}
		p.note("enrollment pending: " + channelCause(err))
		if err := p.sleep(ctx, nodeRetry, nil); err != nil {
			return time.Time{}, err
		}
	}
}

func (p *nodeProcess) report() collector.Report {
	var sources []collector.SourceStatus
	var sourceAsOf time.Time
	if p.sources != nil {
		sources, sourceAsOf = p.sources.Status()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sequence++
	n := len(p.receipts)
	if n > collector.MaxReceipts {
		n = collector.MaxReceipts
	}
	now := p.now()
	if !sourceAsOf.IsZero() {
		now = sourceAsOf
	}
	return collector.Report{Sequence: p.sequence, ObservedAt: now.UTC(), Facts: p.facts, Mechanisms: p.mechanisms, Budget: p.budget.Usage(now), Receipts: append([]collector.Receipt{}, p.receipts[:n]...), Sources: sources}
}

// statusLoop sends the first report at once and then one every
// StatusInterval, sooner (but at least StatusMinimumSpacing apart) when new
// receipts are pending. A failed report keeps its receipts for the next one.
func (p *nodeProcess) statusLoop(ctx context.Context, kick <-chan struct{}) error {
	for {
		p.mu.Lock()
		wait := p.cadence.Wait(p.now())
		p.mu.Unlock()
		if wait > 0 {
			if err := p.sleep(ctx, wait, kick); err != nil {
				return err
			}
			continue
		}
		r := p.report()
		err := p.client.Status(ctx, p.epoch, r)
		if errors.Is(err, node.ErrUnauthenticated) {
			return errNodeReenroll
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			p.note("status pending: " + channelCause(err))
			if err := p.sleep(ctx, nodeRetry, nil); err != nil {
				return err
			}
			continue
		}
		p.note("")
		p.mu.Lock()
		p.receipts = p.receipts[len(r.Receipts):]
		p.cadence.Sent(p.now())
		p.mu.Unlock()
	}
}

// pollLoop long-polls for work and answers each item with a receipt in the
// next report. This build has no recorder, so every item is refused.
func (p *nodeProcess) pollLoop(ctx context.Context, kick chan<- struct{}) error {
	var after uint64
	for {
		// Backpressure: while unreported receipts fill the buffer, do not
		// poll. The cursor only moves past items that have a receipt, so no
		// queued item is skipped; the connector returns the rest again.
		p.mu.Lock()
		full := len(p.receipts) >= nodeReceiptBuffer
		p.mu.Unlock()
		if full {
			select {
			case kick <- struct{}{}:
			default:
			}
			if err := p.sleep(ctx, collector.StatusMinimumSpacing, nil); err != nil {
				return err
			}
			continue
		}
		started := p.now()
		work, err := p.client.Poll(ctx, p.epoch, after)
		if errors.Is(err, node.ErrUnauthenticated) {
			return errNodeReenroll
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			p.note("poll pending: " + channelCause(err))
			if err := p.sleep(ctx, nodeRetry, nil); err != nil {
				return err
			}
			continue
		}
		if len(work) == 0 {
			// The connector holds an empty poll; an early empty answer waits.
			if p.now().Sub(started) < collector.StatusMinimumSpacing {
				if err := p.sleep(ctx, collector.StatusMinimumSpacing, nil); err != nil {
					return err
				}
			}
			continue
		}
		for _, w := range work {
			if w.Sequence <= after {
				continue
			}
			p.mu.Lock()
			full := len(p.receipts) >= nodeReceiptBuffer
			p.mu.Unlock()
			if full {
				break
			}
			// Starting a capture takes the lock for the budget, so decide
			// without holding it.
			r := collector.Decide(w, p.now())
			if w.Kind == collector.WorkPacketCapture && p.packets != nil {
				root := p.root
				if root == nil {
					root = ctx
				}
				r = p.packets.start(root, p.epoch, w)
			}
			if (w.Kind == collector.WorkPacketSource || w.Kind == collector.WorkStopPacketSource) && p.sources != nil {
				root := p.root
				if root == nil {
					root = ctx
				}
				r = p.sources.decide(root, p.epoch, w)
			}
			p.mu.Lock()
			p.receipts = append(p.receipts, r)
			p.mu.Unlock()
			after = w.Sequence
		}
		p.mu.Lock()
		p.cadence.Urgent()
		p.mu.Unlock()
		select {
		case kick <- struct{}{}:
		default:
		}
	}
}

// renewLoop renews one minute before each certificate expires, with the
// same key and epoch, until the session ends.
func (p *nodeProcess) renewLoop(ctx context.Context, notAfter time.Time) error {
	for {
		wait := notAfter.Sub(p.now()) - collector.CertificateRenewal
		if wait < nodeRetry {
			wait = nodeRetry
		}
		if err := p.sleep(ctx, wait, nil); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		next, err := p.enroll(ctx)
		if err != nil {
			return err
		}
		notAfter = next
	}
}

// Run enrolls, then runs the status, poll and renewal loops until ctx ends.
// A connector that no longer knows the process (connector restart) leads to
// a fresh enrollment with the same key and epoch.
func (p *nodeProcess) Run(ctx context.Context) error {
	p.root = ctx
	for {
		notAfter, err := p.enroll(ctx)
		if err != nil {
			return nil
		}
		session, cancel := context.WithCancel(ctx)
		kick := make(chan struct{}, 1)
		done := make(chan error, 3)
		go func() { done <- p.statusLoop(session, kick) }()
		go func() { done <- p.pollLoop(session, kick) }()
		go func() { done <- p.renewLoop(session, notAfter) }()
		<-done
		cancel()
		<-done
		<-done
		if ctx.Err() != nil {
			return nil
		}
	}
}

// NodeDiagnostic is the collector's single stop line: a fixed cause only.
func NodeDiagnostic(err error) string {
	if errors.Is(err, errNodeGuard) {
		return err.Error() + " (" + contracts.NodeDisposableHostGuard + "); the collector runs only on disposable test hosts until it is qualified"
	}
	return "node collector stopped: protected node input, boot ID or process key unavailable"
}
