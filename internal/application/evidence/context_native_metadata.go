package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"sync"
	"time"
)

// Sixteen is the existing installation-wide active worker ceiling. This cache
// contains verified immutable facts only, never authority, credentials, keys or
// payload. A hit does not assert that the regional worker is alive.
const contextNativeMetadataSlots = 16

type contextNativeMetadataKey struct {
	SessionID, WorkerID                  string
	WorkerGeneration                     int64
	Binding                              value.KeyWorkerBinding
	PublicKey                            artifact.Digest
	Preparation                          artifact.DownloadPreparation
	Scope                                artifact.DownloadScope
	Path                                 artifact.DownloadPath
	CreatedAt, SessionUntil, WorkerUntil time.Time
}

func contextMetadataKey(session artifact.DownloadSession, o ContextDownloadAttachment, a artifact.DownloadAuthority) (contextNativeMetadataKey, error) {
	if !session.Valid() || o.Worker == nil || o.Enrollment == nil || o.Preparation == nil || !o.Preparation.Valid() || o.Scope != session.Scope || a.Scope != session.Scope || !a.Environment.Path.Valid() {
		return contextNativeMetadataKey{}, artifact.ErrDownloadUnavailable
	}
	return contextNativeMetadataKey{SessionID: session.ID, WorkerID: o.Intent.ID, WorkerGeneration: o.Intent.Generation, Binding: o.Worker.Binding, PublicKey: o.Enrollment.PublicKeyDigest, Preparation: *o.Preparation, Scope: session.Scope, Path: a.Environment.Path, CreatedAt: session.CreatedAt, SessionUntil: session.Deadline, WorkerUntil: o.Intent.RunUntil}, nil
}
func (k contextNativeMetadataKey) valid() bool {
	return value.UUID(k.SessionID) && value.UUID(k.WorkerID) && k.WorkerGeneration == 1 && k.Binding.Valid() && k.Binding.DownloadID == k.SessionID && k.PublicKey != (artifact.Digest{}) && k.Preparation.Valid() && k.Preparation.SessionID == k.SessionID && k.Scope.Valid() && k.Path.Valid() && !k.CreatedAt.IsZero() && k.CreatedAt.Before(k.WorkerUntil) && !k.WorkerUntil.After(k.SessionUntil)
}

type contextNativeMetadataEntry struct {
	key            contextNativeMetadataKey
	facts          artifact.NativeDownloadMetadata
	until, lastUse time.Time
	ready, failed  bool
	loading        chan struct{}
	pins           int
}
type contextNativeMetadata struct {
	mu       sync.Mutex
	entries  map[string]*contextNativeMetadataEntry
	handoffs map[string]artifact.PreparedDownload
	closed   bool
	now      func() time.Time
}

func newContextNativeMetadata(now func() time.Time) *contextNativeMetadata {
	return &contextNativeMetadata{entries: map[string]*contextNativeMetadataEntry{}, handoffs: map[string]artifact.PreparedDownload{}, now: now}
}

// handoff keeps one acknowledged preparation's verified facts for this
// process's first load of that exact preparation, so the same request need not
// repeat a worker Observe conversation. It is not authority: prepared() still
// performs every current check, get() validates facts and applies the key's
// original bounds, and the handoff is consumed once. When all slots are taken
// the later load observes the worker exactly as before.
func (c *contextNativeMetadata) handoff(p artifact.PreparedDownload) {
	if c == nil || !p.Valid() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.now()
	for id, h := range c.handoffs {
		if !n.Before(h.Native.ReadUntil) {
			delete(c.handoffs, id)
		}
	}
	if _, ok := c.handoffs[p.Preparation.SessionID]; c.closed || !n.Before(p.Native.ReadUntil) || !ok && len(c.handoffs) >= contextNativeMetadataSlots {
		return
	}
	c.handoffs[p.Preparation.SessionID] = p
}

func (c *contextNativeMetadata) takeHandoff(k contextNativeMetadataKey) (artifact.NativeDownloadMetadata, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.handoffs[k.SessionID]
	delete(c.handoffs, k.SessionID)
	if !ok || c.closed || p.Preparation != k.Preparation || p.Scope != k.Scope || !c.now().Before(p.Native.ReadUntil) {
		return artifact.NativeDownloadMetadata{}, false
	}
	return p.Native, true
}
func (c *contextNativeMetadata) prune() {
	n := c.now()
	for id, e := range c.entries {
		if e.pins == 0 && e.loading == nil && !n.Before(e.until) {
			delete(c.entries, id)
		}
	}
}
func (c *contextNativeMetadata) makeRoom() bool {
	if len(c.entries) < contextNativeMetadataSlots {
		return true
	}
	var oldest *contextNativeMetadataEntry
	for _, e := range c.entries {
		// Failed/unknown loads retain a bounded negative result until expiry. An
		// unrelated cache miss must not turn repeated status polls into new attempts.
		if e.pins == 0 && e.loading == nil && !e.failed && (oldest == nil || e.lastUse.Before(oldest.lastUse)) {
			oldest = e
		}
	}
	if oldest == nil {
		return false
	}
	delete(c.entries, oldest.key.SessionID)
	return true
}

// A miss belongs to this exact caller. Waiters wait within their own original
// contexts and independently reauthorize afterward. They never take over a
// failed load, borrow a leader's identity or reset either request's deadline.
// The SQL Observe claim repeats the busy/capacity predicate atomically; this
// snapshot prevents needless I/O but cannot itself authorize that claim.
func (c *contextNativeMetadata) get(ctx context.Context, k contextNativeMetadataKey, mayObserve, pin bool, load func(context.Context) (artifact.NativeDownloadMetadata, error)) (artifact.NativeDownloadMetadata, func(), error) {
	var zero artifact.NativeDownloadMetadata
	if c == nil || ctx == nil || ctx.Err() != nil || load == nil || !k.valid() {
		return zero, nil, artifact.ErrDownloadUnavailable
	}
	for {
		c.mu.Lock()
		c.prune()
		if c.closed || ctx.Err() != nil || !c.now().Before(k.SessionUntil) || !c.now().Before(k.WorkerUntil) {
			c.mu.Unlock()
			return zero, nil, artifact.ErrDownloadExpired
		}
		existing := c.entries[k.SessionID]
		if existing != nil && existing.key != k {
			c.mu.Unlock()
			return zero, nil, artifact.ErrDownloadUnavailable
		}
		if existing != nil && existing.loading != nil {
			done := existing.loading
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return zero, nil, artifact.ErrDownloadExpired
			case <-done:
			}
			c.mu.Lock()
			next := c.entries[k.SessionID]
			usable := next == existing && next.ready && next.loading == nil
			c.mu.Unlock()
			if !usable {
				return zero, nil, artifact.ErrDownloadUnavailable
			}
			continue
		}
		if existing != nil && existing.failed {
			c.mu.Unlock()
			return zero, nil, ErrDownloadMetadataUnavailable
		}
		if existing != nil && existing.ready {
			if !c.now().Before(existing.until) {
				c.mu.Unlock()
				return zero, nil, artifact.ErrDownloadExpired
			}
			existing.lastUse = c.now()
			release := func() {}
			if pin {
				existing.pins++
				release = c.release(existing)
			}
			facts := existing.facts
			c.mu.Unlock()
			return facts, release, nil
		}
		if !mayObserve {
			c.mu.Unlock()
			return zero, nil, ErrDownloadMetadataUnavailable
		}
		if !c.makeRoom() {
			c.mu.Unlock()
			return zero, nil, artifact.ErrDownloadCapacity
		}
		e := &contextNativeMetadataEntry{key: k, loading: make(chan struct{}), until: identity.Earlier(k.SessionUntil, k.WorkerUntil), lastUse: c.now()}
		c.entries[k.SessionID] = e
		c.mu.Unlock()
		facts, err := load(ctx)
		c.mu.Lock()
		valid := err == nil && !c.closed && ctx.Err() == nil && c.entries[k.SessionID] == e && c.now().Before(e.until) && (artifact.PreparedDownload{Preparation: k.Preparation, Scope: k.Scope, Native: facts}).Valid() && facts.ReadUntil.After(c.now()) && facts.ReadUntil.Before(facts.DeleteBy)
		if valid {
			e.facts = facts
			e.until = identity.Earlier(e.until, facts.ReadUntil)
			e.ready = true
		} else {
			e.failed = true
		}
		done := e.loading
		e.loading = nil
		close(done)
		if !valid {
			if c.closed {
				delete(c.entries, k.SessionID)
			}
			c.mu.Unlock()
			if err != nil {
				return zero, nil, err
			}
			return zero, nil, ErrDownloadMetadataUnavailable
		}
		release := func() {}
		if pin {
			e.pins++
			release = c.release(e)
		}
		c.mu.Unlock()
		return facts, release, nil
	}
}
func (c *contextNativeMetadata) release(e *contextNativeMetadataEntry) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			e.pins--
			if e.pins == 0 && e.loading == nil && (c.closed || !c.now().Before(e.until)) {
				if c.entries[e.key.SessionID] == e {
					delete(c.entries, e.key.SessionID)
				}
			}
		})
	}
}
func (c *contextNativeMetadata) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	clear(c.handoffs)
	for id, e := range c.entries {
		if e.pins == 0 && e.loading == nil {
			delete(c.entries, id)
		}
	}
}
