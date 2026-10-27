// Package delivery owns peer work transport state (C-19). NodeChannel is the
// connector side of the private node work channel (ADR-246, I-02): it admits
// attested collector processes, issues their short client certificates,
// holds one bounded work queue per node process and keeps each node's latest
// status in memory. It owns no SQL state; a connector restart forgets every
// node, whose collectors then enroll again.
package delivery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/collector"
)

var (
	ErrNodeInvalid         = errors.New("node channel: invalid request")
	ErrNodeDenied          = errors.New("node channel: attestation denied")
	ErrNodeUnauthenticated = errors.New("node channel: unknown or replaced node process")
	ErrNodeConflict        = errors.New("node channel: stale node process")
	ErrNodeRateLimited     = errors.New("node channel: report too soon")
	ErrNodeLimit           = errors.New("node channel: node or work limit reached")
	ErrNodeUnavailable     = errors.New("node channel: unavailable")
)

// MaxNodes bounds the in-memory registry: the Kubernetes scalability limit of
// 5,000 nodes per cluster.
const MaxNodes = 5000

// NodeAttester verifies a Pod-bound collector token against current
// Kubernetes state: the token's Pod must be a running Pod of the installed
// collector DaemonSet, and the claimed boot ID must equal its Node's
// kubelet-reported boot ID. The returned identity has no Epoch.
type NodeAttester interface {
	AttestNode(ctx context.Context, token []byte, bootID string) (collector.Identity, error)
}

// NodeIssuer signs an identity-free CSR for an attested identity and returns
// the DER certificate and the SHA-256 digest of that DER.
type NodeIssuer interface {
	IssueNode(csr []byte, id collector.Identity, notAfter time.Time) ([]byte, [32]byte, error)
}

// NodePeer is the authenticated node process behind one certificate.
type NodePeer struct {
	NodeUID string
	Epoch   string
}

// NodeView is one node's current view for the connector's own use. Current
// is derived at read time: a report within StatusStaleAfter.
type NodeView struct {
	Identity   collector.Identity
	EnrolledAt time.Time
	Report     *collector.Report
	ReportedAt time.Time
	Reports    uint64
	Current    bool
	Queued     int
}

type nodeEntry struct {
	id         collector.Identity
	enrolledAt time.Time
	certs      map[[32]byte]time.Time
	report     *collector.Report
	reportedAt time.Time
	reports    uint64
	work       []collector.Work
	nextSeq    uint64
	wake       chan struct{}
}

type NodeChannel struct {
	attester NodeAttester
	issuer   NodeIssuer
	now      func() time.Time
	mu       sync.Mutex
	nodes    map[string]*nodeEntry
	certs    map[[32]byte]string
	onChange func(NodeView)
}

// NewNodeChannel composes the channel. onChange, when set, is called outside
// the lock after each enrollment and each report whose assessment changed.
func NewNodeChannel(a NodeAttester, i NodeIssuer, now func() time.Time, onChange func(NodeView)) (*NodeChannel, error) {
	if a == nil || i == nil || now == nil {
		return nil, ErrNodeInvalid
	}
	return &NodeChannel{attester: a, issuer: i, now: now, nodes: map[string]*nodeEntry{}, certs: map[[32]byte]string{}, onChange: onChange}, nil
}

func validID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// Enroll attests the token, signs the CSR and makes this process the node's
// current collector generation. A renewal by the same Pod, boot and epoch adds
// a certificate and keeps the previous one until it expires. Any other
// enrollment for the node replaces the earlier process: its certificates stop
// authenticating, its queued work is dropped and its open poll ends.
func (c *NodeChannel) Enroll(ctx context.Context, token, csr []byte, bootID, epoch string) ([]byte, time.Time, collector.Identity, error) {
	if ctx == nil || len(token) == 0 || len(csr) == 0 || !validID(bootID) || !validID(epoch) {
		return nil, time.Time{}, collector.Identity{}, ErrNodeInvalid
	}
	id, err := c.attester.AttestNode(ctx, token, bootID)
	if err != nil {
		if ctx.Err() != nil {
			return nil, time.Time{}, collector.Identity{}, ErrNodeUnavailable
		}
		return nil, time.Time{}, collector.Identity{}, err
	}
	if id.NodeUID == "" || id.PodUID == "" || id.BootID != bootID || id.Epoch != "" {
		return nil, time.Time{}, collector.Identity{}, ErrNodeDenied
	}
	id.Epoch = epoch
	now := c.now()
	notAfter := now.Add(collector.CertificateLifetime).UTC().Truncate(time.Second)
	der, digest, err := c.issuer.IssueNode(csr, id, notAfter)
	if err != nil {
		return nil, time.Time{}, collector.Identity{}, ErrNodeInvalid
	}
	c.mu.Lock()
	e := c.nodes[id.NodeUID]
	if e == nil && len(c.nodes) >= MaxNodes {
		c.mu.Unlock()
		return nil, time.Time{}, collector.Identity{}, ErrNodeLimit
	}
	if e != nil && e.id.PodUID == id.PodUID && e.id.BootID == id.BootID && e.id.Epoch == id.Epoch {
		for d, until := range e.certs {
			if !now.Before(until) {
				delete(e.certs, d)
				delete(c.certs, d)
			}
		}
		// The current certificate plus at most one earlier one during overlap.
		for len(e.certs) >= 2 {
			var oldest [32]byte
			first := true
			for d, until := range e.certs {
				if first || until.Before(e.certs[oldest]) {
					oldest, first = d, false
				}
			}
			delete(e.certs, oldest)
			delete(c.certs, oldest)
		}
	} else {
		if e != nil {
			for d := range e.certs {
				delete(c.certs, d)
			}
			close(e.wake)
		}
		e = &nodeEntry{id: id, enrolledAt: now, certs: map[[32]byte]time.Time{}, wake: make(chan struct{})}
		c.nodes[id.NodeUID] = e
	}
	e.certs[digest] = notAfter
	c.certs[digest] = id.NodeUID
	view := c.view(e, now)
	c.mu.Unlock()
	if c.onChange != nil {
		c.onChange(view)
	}
	return der, notAfter, id, nil
}

// Peer maps a verified client certificate's digest to its current process.
func (c *NodeChannel) Peer(digest [32]byte) (NodePeer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	uid, ok := c.certs[digest]
	e := c.nodes[uid]
	if !ok || e == nil || !c.now().Before(e.certs[digest]) {
		return NodePeer{}, ErrNodeUnauthenticated
	}
	return NodePeer{NodeUID: uid, Epoch: e.id.Epoch}, nil
}

func (c *NodeChannel) current(p NodePeer, epoch string) (*nodeEntry, error) {
	e := c.nodes[p.NodeUID]
	if e == nil || e.id.Epoch != p.Epoch {
		return nil, ErrNodeUnauthenticated
	}
	if epoch != p.Epoch {
		return nil, ErrNodeConflict
	}
	return e, nil
}

// Poll returns queued work after the given sequence, waiting up to hold for
// new work. A replaced process's poll ends with ErrNodeUnauthenticated.
func (c *NodeChannel) Poll(ctx context.Context, p NodePeer, epoch string, after uint64, hold time.Duration) ([]collector.Work, error) {
	if ctx == nil || hold < 0 || hold > collector.PollHold {
		return nil, ErrNodeInvalid
	}
	timer := time.NewTimer(hold)
	defer timer.Stop()
	for {
		c.mu.Lock()
		e, err := c.current(p, epoch)
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		now := c.now()
		var out []collector.Work
		for _, w := range e.work {
			if w.Sequence > after && now.Before(w.NotAfter) && len(out) < collector.MaxWorkPerPoll {
				out = append(out, w)
			}
		}
		wake := e.wake
		c.mu.Unlock()
		if len(out) > 0 {
			return out, nil
		}
		select {
		case <-ctx.Done():
			return nil, ErrNodeUnavailable
		case <-timer.C:
			return []collector.Work{}, nil
		case <-wake:
		}
	}
}

func sameAssessment(a, b []collector.Availability) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Mechanism != b[i].Mechanism || a[i].Adapter != b[i].Adapter || a[i].Prerequisites != b[i].Prerequisites || a[i].Hook != b[i].Hook || len(a[i].Reasons) != len(b[i].Reasons) {
			return false
		}
		for j := range a[i].Reasons {
			if a[i].Reasons[j] != b[i].Reasons[j] {
				return false
			}
		}
	}
	return true
}

// Report stores the node's latest status. Sequences only grow and reports
// closer than StatusMinimumSpacing are refused. Receipts remove the work they
// answer from the queue.
func (c *NodeChannel) Report(p NodePeer, epoch string, r collector.Report) error {
	if r.Sequence == 0 || r.ObservedAt.IsZero() || len(r.Receipts) > collector.MaxReceipts || len(r.Mechanisms) > 8 {
		return ErrNodeInvalid
	}
	for _, rc := range r.Receipts {
		if (rc.Outcome != collector.OutcomeAccepted && rc.Outcome != collector.OutcomeRefused) || (rc.Reason != "" && !rc.Reason.Valid()) {
			return ErrNodeInvalid
		}
	}
	c.mu.Lock()
	e, err := c.current(p, epoch)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	now := c.now()
	if e.report != nil && (r.Sequence <= e.report.Sequence) {
		c.mu.Unlock()
		return ErrNodeConflict
	}
	if e.report != nil && now.Sub(e.reportedAt) < collector.StatusMinimumSpacing {
		c.mu.Unlock()
		return ErrNodeRateLimited
	}
	changed := e.report == nil || !sameAssessment(e.report.Mechanisms, r.Mechanisms)
	answered := map[uint64]bool{}
	for _, rc := range r.Receipts {
		answered[rc.Sequence] = true
	}
	kept := e.work[:0]
	for _, w := range e.work {
		if !answered[w.Sequence] && now.Before(w.NotAfter) {
			kept = append(kept, w)
		}
	}
	e.work = kept
	stored := r
	e.report, e.reportedAt = &stored, now
	e.reports++
	view := c.view(e, now)
	c.mu.Unlock()
	if changed && c.onChange != nil {
		c.onChange(view)
	}
	return nil
}

// Enqueue queues one work item for the node's current process and wakes its
// poll. Later increments are the producers; this increment has none.
func (c *NodeChannel) Enqueue(nodeUID string, kind collector.WorkKind, notAfter time.Time) (collector.Work, error) {
	if !kind.Valid() {
		return collector.Work{}, ErrNodeInvalid
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return collector.Work{}, ErrNodeUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.nodes[nodeUID]
	now := c.now()
	if e == nil || !now.Before(notAfter) {
		return collector.Work{}, ErrNodeUnavailable
	}
	if len(e.work) >= collector.MaxQueuedWork {
		return collector.Work{}, ErrNodeLimit
	}
	e.nextSeq++
	h := hex.EncodeToString(raw[:])
	w := collector.Work{ID: h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], Sequence: e.nextSeq, Kind: kind, NotAfter: notAfter}
	e.work = append(e.work, w)
	close(e.wake)
	e.wake = make(chan struct{})
	return w, nil
}

func (c *NodeChannel) view(e *nodeEntry, now time.Time) NodeView {
	v := NodeView{Identity: e.id, EnrolledAt: e.enrolledAt, ReportedAt: e.reportedAt, Reports: e.reports, Queued: len(e.work)}
	if e.report != nil {
		r := *e.report
		v.Report = &r
		v.Current = now.Sub(e.reportedAt) <= collector.StatusStaleAfter
	}
	return v
}

// Nodes returns every enrolled node, ordered by node name.
func (c *NodeChannel) Nodes() []NodeView {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	out := make([]NodeView, 0, len(c.nodes))
	for _, e := range c.nodes {
		out = append(out, c.view(e, now))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity.NodeName < out[j].Identity.NodeName })
	return out
}
