package configuration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"slices"
	"sync"
	"time"

	value "asservat.local/asservat/internal/domain/configuration"
)

// NamespaceJournalIdle stops a connector's namespace journal no caller has
// read for this long (ADR-247).
const NamespaceJournalIdle = 2 * time.Minute

// NamespaceJournalSnapshot is one consistent journal state: its ID and
// sequence, the start of its latest LIST or clean watch session, and the
// namespaces with journal versions.
type NamespaceJournalSnapshot struct {
	Journal    string
	Sequence   int64
	ObservedAt time.Time
	Namespaces []value.ObservedNamespace
}

// NamespaceJournalService keeps one continuous namespace journal for the
// regional connector's own cluster (ADR-247): a LIST followed by finite
// watch sessions resumed from the last delivered cursor, every transition
// applied in order. Callers read snapshots; versions change only when an
// observed key value changes, so the hub keeps an assignment across
// unrelated namespace writes but not across A -> B -> A. A changed key set,
// expired history or an invalid transition starts a new journal with a new ID.
// The journal stops after NamespaceJournalIdle without a reader.
//
// Each started feed owns its journal: a restart swaps in a new feed under
// the lock and cancels the old one, whose late deliveries are discarded, so
// concurrent restarts never mix key sets or leak a running feed.
type NamespaceJournalService struct {
	Observer NamespaceObserver
	Now      func() time.Time

	mu       sync.Mutex
	feed     *namespaceJournalFeed
	lastRead time.Time
}

type namespaceJournalFeed struct {
	keys    value.NamespaceKeys
	id      string
	journal *NamespaceJournal
	// stopped marks a feed that went idle or was poisoned: the next reader
	// starts a new one.
	stopped bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func newJournalID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// Snapshot returns the journal of keys, starting it when needed. A journal
// that has no complete LIST yet is unavailable.
func (s *NamespaceJournalService) Snapshot(ctx context.Context, keys value.NamespaceKeys) (NamespaceJournalSnapshot, error) {
	if s == nil || s.Observer == nil || s.Now == nil || !keys.Valid() || len(keys.Labels)+len(keys.Annotations) == 0 {
		return NamespaceJournalSnapshot{}, value.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRead = s.Now()
	f := s.feed
	if f == nil || f.stopped || !slices.Equal(f.keys.Labels, keys.Labels) || !slices.Equal(f.keys.Annotations, keys.Annotations) {
		if f != nil {
			f.cancel() // its later deliveries no longer match s.feed
		}
		f = s.startLocked(keys)
		s.feed = f
	}
	if f.journal == nil {
		return NamespaceJournalSnapshot{}, value.ErrUnavailable
	}
	o := f.journal.VersionedObservation(f.id)
	if o == nil {
		return NamespaceJournalSnapshot{}, value.ErrUnavailable
	}
	return NamespaceJournalSnapshot{Journal: f.id, Sequence: f.journal.Sequence(), ObservedAt: f.journal.ObservedAt(), Namespaces: o.Namespaces}, nil
}

// Close stops the journal and joins its feed.
func (s *NamespaceJournalService) Close() {
	s.mu.Lock()
	f := s.feed
	s.feed = nil
	s.mu.Unlock()
	if f != nil {
		f.cancel()
		<-f.done
	}
}

func (s *NamespaceJournalService) startLocked(keys value.NamespaceKeys) *namespaceJournalFeed {
	ctx, cancel := context.WithCancel(context.Background())
	f := &namespaceJournalFeed{keys: keys, cancel: cancel, done: make(chan struct{})}
	items := make(chan namespaceItem, 1)
	go func() {
		defer close(f.done)
		feed := make(chan struct{})
		go func() {
			defer close(feed)
			runNamespaceFeed(ctx, s.Observer, keys, s.Now, items)
		}()
		idle := time.NewTicker(10 * time.Second)
		defer idle.Stop()
		for {
			select {
			case <-ctx.Done():
				<-feed
				return
			case <-idle.C:
				s.mu.Lock()
				stale := s.feed == f && s.Now().Sub(s.lastRead) > NamespaceJournalIdle
				if stale {
					f.journal, f.stopped = nil, true
				}
				s.mu.Unlock()
				if stale {
					cancel()
				}
			case it := <-items:
				s.apply(f, it)
			}
		}
	}()
	return f
}

// apply advances f's journal by one feed delivery, under the lock; a
// delivery of a feed that is no longer current is dropped.
func (s *NamespaceJournalService) apply(f *namespaceJournalFeed, it namespaceItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.feed != f || f.stopped {
		return
	}
	switch {
	case it.list != nil:
		j, err := NewNamespaceJournal(*it.list)
		if err != nil {
			f.journal, f.stopped = nil, true
			return
		}
		f.journal, f.id = j, newJournalID()
	case it.event != nil:
		if f.journal != nil && f.journal.Apply(*it.event) != nil {
			// A poisoned journal reports nothing; the next reader relists.
			f.journal, f.stopped = nil, true
		}
	default:
		if f.journal != nil {
			f.journal.Fresh(it.fresh)
		}
	}
}
