package presentation

import "sync"

// ChangeSubscription delivers the IDs whose state changed since the last
// Take. An empty ID means anything may have changed (listener reconnect).
type ChangeSubscription interface {
	Ready() <-chan struct{}
	Take() map[string]struct{}
	Close()
}

// Changes fans published IDs out to status streams and waits. An empty ID means
// anything may have changed (for example after a listener reconnect).
type Changes struct {
	mu   sync.Mutex
	subs map[*changeSubscription]struct{}
}

type changeSubscription struct {
	changes *Changes
	watched map[string]bool
	ready   chan struct{}
	pending map[string]struct{}
}

func NewChanges() *Changes { return &Changes{subs: map[*changeSubscription]struct{}{}} }

func (c *Changes) Publish(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for s := range c.subs {
		if id != "" && !s.watched[id] {
			continue
		}
		s.pending[id] = struct{}{}
		select {
		case s.ready <- struct{}{}:
		default:
		}
	}
}

// Subscribe registers a subscriber for the watched IDs until Close. It
// receives only those IDs and the "" any-change marker.
func (c *Changes) Subscribe(ids []string) ChangeSubscription {
	watched := make(map[string]bool, len(ids))
	for _, id := range ids {
		watched[id] = true
	}
	s := &changeSubscription{changes: c, watched: watched, ready: make(chan struct{}, 1), pending: map[string]struct{}{}}
	c.mu.Lock()
	c.subs[s] = struct{}{}
	c.mu.Unlock()
	return s
}

func (s *changeSubscription) Ready() <-chan struct{} { return s.ready }

func (s *changeSubscription) Take() map[string]struct{} {
	s.changes.mu.Lock()
	defer s.changes.mu.Unlock()
	out := s.pending
	s.pending = map[string]struct{}{}
	return out
}

func (s *changeSubscription) Close() {
	s.changes.mu.Lock()
	delete(s.changes.subs, s)
	s.changes.mu.Unlock()
}
