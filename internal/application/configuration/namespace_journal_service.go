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
type NamespaceJournalService struct {
	Observer NamespaceObserver
	Now      func() time.Time

	mu       sync.Mutex
	keys     value.NamespaceKeys
	id       string
	journal  *NamespaceJournal
	cancel   context.CancelFunc
	done     chan struct{}
	lastRead time.Time
	// stopped marks a journal that went idle or was poisoned: the next
	// reader starts a new one.
	stopped bool
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
	if s.cancel == nil || s.stopped || !slices.Equal(s.keys.Labels, keys.Labels) || !slices.Equal(s.keys.Annotations, keys.Annotations) {
		s.restartLocked(keys)
	}
	if s.journal == nil {
		return NamespaceJournalSnapshot{}, value.ErrUnavailable
	}
	o := s.journal.VersionedObservation(s.id)
	if o == nil {
		return NamespaceJournalSnapshot{}, value.ErrUnavailable
	}
	return NamespaceJournalSnapshot{Journal: s.id, Sequence: s.journal.Sequence(), ObservedAt: s.journal.ObservedAt(), Namespaces: o.Namespaces}, nil
}

// Close stops the journal.
func (s *NamespaceJournalService) Close() {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel, s.done, s.journal = nil, nil, nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (s *NamespaceJournalService) restartLocked(keys value.NamespaceKeys) {
	if s.cancel != nil {
		cancel, done := s.cancel, s.done
		s.mu.Unlock()
		cancel()
		<-done
		s.mu.Lock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.keys, s.journal, s.id, s.stopped = keys, nil, "", false
	s.cancel, s.done = cancel, make(chan struct{})
	items := make(chan namespaceItem, 1)
	done := s.done
	go func() {
		defer close(done)
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
				stale := s.Now().Sub(s.lastRead) > NamespaceJournalIdle
				if stale {
					s.journal, s.stopped = nil, true
				}
				s.mu.Unlock()
				if stale {
					cancel()
				}
			case it := <-items:
				s.apply(it)
			}
		}
	}()
}

// apply advances the journal by one feed delivery, under the lock.
func (s *NamespaceJournalService) apply(it namespaceItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case it.list != nil:
		j, err := NewNamespaceJournal(*it.list)
		if err != nil {
			s.journal, s.stopped = nil, true
			return
		}
		s.journal, s.id = j, newJournalID()
	case it.event != nil:
		if s.journal != nil && s.journal.Apply(*it.event) != nil {
			// A poisoned journal reports nothing; the next reader relists.
			s.journal, s.stopped = nil, true
		}
	default:
		if s.journal != nil {
			s.journal.Fresh(it.fresh)
		}
	}
}
