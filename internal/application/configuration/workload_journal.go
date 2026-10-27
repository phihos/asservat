package configuration

import (
	"cmp"
	"context"
	"errors"
	"io"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"

	value "asservat.local/asservat/internal/domain/configuration"
)

// WorkloadObserver lists and watches one kind of workload of the connector's
// cluster, selected server-side by a label selector and reduced to keys
// (ADR-247). Items carry their namespace name only; NamespaceUIDs resolves
// names. Watches end with io.EOF cleanly and value.ErrChanged when history
// is gone.
type WorkloadObserver interface {
	ListWorkloads(context.Context, string, value.WorkloadSelection) (string, []value.ObservedWorkload, error)
	WatchWorkloads(context.Context, string, string, value.WorkloadSelection) (WorkloadWatch, error)
	NamespaceUIDs(context.Context) (map[string]string, error)
}
type WorkloadWatch interface {
	Next(context.Context) (WorkloadEvent, error)
	Close()
}
type WorkloadEvent struct {
	Type, ResourceVersion string
	Workload              *value.ObservedWorkload
}

// workloadJournal is the state of one selection across both kinds: every
// transition applied in order, with per-workload change counters of the
// observed values, like NamespaceJournal (ADR-247).
type workloadJournal struct {
	byUID    map[string]value.ObservedWorkload
	changes  map[string]int64
	sequence int64
}

func (j *workloadJournal) set(w value.ObservedWorkload) {
	old, exists := j.byUID[w.UID]
	same := exists && old.Deleting == w.Deleting && maps.Equal(old.Labels, w.Labels) && maps.Equal(old.Annotations, w.Annotations)
	if !same {
		j.changes[w.UID]++
		j.sequence++
	}
	w.Labels, w.Annotations = maps.Clone(w.Labels), maps.Clone(w.Annotations)
	j.byUID[w.UID] = w
}

// WorkloadJournalSnapshot is one consistent state of a selection's journal.
type WorkloadJournalSnapshot struct {
	Journal    string
	Sequence   int64
	ObservedAt time.Time
	Workloads  []value.ObservedWorkload
}

// WorkloadJournalService keeps continuous journals of at most four workload
// selections of the connector's own cluster (ADR-247): per kind a LIST then
// finite watch sessions resumed from the last cursor. A journal's versions
// "<journal>:<changes>" change only when an observed value changes; a relist
// or invalid transition starts a new journal ID. Namespace names are
// resolved to UIDs from a namespace LIST every 30 seconds, and at most once a second
// when a workload not present at the last LIST appears. A journal
// stops after NamespaceJournalIdle without a reader.
type WorkloadJournalService struct {
	Observer WorkloadObserver
	Now      func() time.Time

	mu        sync.Mutex
	journals  map[string]*workloadFeed
	uids      map[string]string
	uidsAt    time.Time
	uidsError error
	// resolved are the workload UIDs present at the last namespace LIST: a
	// new workload (such as one in a recreated namespace) rereads the names
	// at most once a second rather than waiting for the 30-second refresh.
	resolved map[string]bool
}

const maxWorkloadJournals = 4

type workloadFeed struct {
	selection value.WorkloadSelection
	id        string
	journal   *workloadJournal
	// listed counts kinds whose current LIST was applied; observed is the
	// earliest start of each kind's latest LIST or clean watch session.
	listed   map[string]bool
	observed map[string]time.Time
	lastRead time.Time
	// generation counts journal resets; a kind whose LIST predates the
	// current generation lists again.
	generation int
	cancel     context.CancelFunc
	done       chan struct{}
}

// Snapshot returns the journal of a selection, starting it when needed.
func (s *WorkloadJournalService) Snapshot(ctx context.Context, sel value.WorkloadSelection) (WorkloadJournalSnapshot, error) {
	if s == nil || s.Observer == nil || s.Now == nil || !sel.Valid() {
		return WorkloadJournalSnapshot{}, value.ErrInvalid
	}
	key := value.SelectionKey(sel)
	s.mu.Lock()
	if s.journals == nil {
		s.journals = map[string]*workloadFeed{}
	}
	f := s.journals[key]
	if f == nil {
		if len(s.journals) >= maxWorkloadJournals {
			s.mu.Unlock()
			return WorkloadJournalSnapshot{}, value.ErrLimit
		}
		f = s.startLocked(sel)
		s.journals[key] = f
	}
	f.lastRead = s.Now()
	if f.journal == nil || len(f.listed) != len(value.WorkloadKinds) {
		s.mu.Unlock()
		return WorkloadJournalSnapshot{}, value.ErrUnavailable
	}
	out := WorkloadJournalSnapshot{Journal: f.id, Sequence: f.journal.sequence}
	for _, kind := range value.WorkloadKinds {
		if at := f.observed[kind]; out.ObservedAt.IsZero() || at.Before(out.ObservedAt) {
			out.ObservedAt = at
		}
	}
	for _, w := range f.journal.byUID {
		w.Labels, w.Annotations = maps.Clone(w.Labels), maps.Clone(w.Annotations)
		w.ResourceVersion = f.id + ":" + strconv.FormatInt(f.journal.changes[w.UID], 10)
		out.Workloads = append(out.Workloads, w)
	}
	age := s.Now().Sub(s.uidsAt)
	refresh := s.uids == nil || age >= 30*time.Second
	if !refresh && age >= time.Second {
		refresh = slices.ContainsFunc(out.Workloads, func(w value.ObservedWorkload) bool { return !s.resolved[w.UID] })
	}
	s.mu.Unlock()
	if refresh {
		uids, err := s.Observer.NamespaceUIDs(ctx)
		resolved := make(map[string]bool, len(out.Workloads))
		for _, w := range out.Workloads {
			resolved[w.UID] = true
		}
		s.mu.Lock()
		s.uids, s.uidsAt, s.uidsError, s.resolved = uids, s.Now(), err, resolved
		s.mu.Unlock()
	}
	s.mu.Lock()
	uids, err := s.uids, s.uidsError
	s.mu.Unlock()
	if err != nil || uids == nil {
		return WorkloadJournalSnapshot{}, value.ErrUnavailable
	}
	// A workload of a namespace not (yet) resolved is omitted: it grants
	// nothing until the next namespace LIST names its namespace.
	kept := out.Workloads[:0]
	for _, w := range out.Workloads {
		if uid := uids[w.Namespace.Name]; uid != "" {
			w.Namespace.UID = uid
			kept = append(kept, w)
		}
	}
	out.Workloads = kept
	slices.SortFunc(out.Workloads, func(a, b value.ObservedWorkload) int { return cmp.Compare(a.UID, b.UID) })
	return out, nil
}

// Close stops every journal.
func (s *WorkloadJournalService) Close() {
	s.mu.Lock()
	feeds := slices.Collect(maps.Values(s.journals))
	s.journals = nil
	s.mu.Unlock()
	for _, f := range feeds {
		f.cancel()
		<-f.done
	}
}

func (s *WorkloadJournalService) startLocked(sel value.WorkloadSelection) *workloadFeed {
	ctx, cancel := context.WithCancel(context.Background())
	f := &workloadFeed{selection: sel, cancel: cancel, done: make(chan struct{}), lastRead: s.Now()}
	s.resetLocked(f)
	var wg sync.WaitGroup
	for _, kind := range value.WorkloadKinds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.follow(ctx, f, kind)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.mu.Lock()
				idle := s.Now().Sub(f.lastRead) > NamespaceJournalIdle
				if idle && s.journals[value.SelectionKey(sel)] == f {
					delete(s.journals, value.SelectionKey(sel))
				}
				s.mu.Unlock()
				if idle {
					cancel()
					return
				}
			}
		}
	}()
	go func() { wg.Wait(); close(f.done) }()
	return f
}

// resetLocked starts a new journal: every kind must list again.
func (s *WorkloadJournalService) resetLocked(f *workloadFeed) {
	f.id, f.journal = newJournalID(), &workloadJournal{byUID: map[string]value.ObservedWorkload{}, changes: map[string]int64{}}
	f.listed, f.observed = map[string]bool{}, map[string]time.Time{}
	f.generation++
}

// follow runs one kind's LIST and watch sessions. A relist of any kind, or
// an invalid transition, starts a new journal for the whole selection.
func (s *WorkloadJournalService) follow(ctx context.Context, f *workloadFeed, kind string) {
	pause := func() bool {
		t := time.NewTimer(time.Second)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	}
	valid := func(w value.ObservedWorkload) bool {
		w.Namespace.UID = "-"
		return w.Kind == kind && w.Valid(f.selection.Keys, true)
	}
	for ctx.Err() == nil {
		start := s.Now()
		cursor, items, err := s.Observer.ListWorkloads(ctx, kind, f.selection)
		if err == nil && len(items) > value.MaxObservedWorkloads {
			err = value.ErrLimit
		}
		for _, w := range items {
			if err == nil && !valid(w) {
				err = value.ErrInvalid
			}
		}
		if err != nil {
			if !pause() {
				return
			}
			continue
		}
		s.mu.Lock()
		if f.listed[kind] {
			// A second LIST cannot claim continuity with the first.
			s.resetLocked(f)
		}
		for uid, w := range f.journal.byUID {
			if w.Kind == kind {
				delete(f.journal.byUID, uid)
			}
		}
		for _, w := range items {
			f.journal.set(w)
		}
		f.listed[kind], f.observed[kind] = true, start
		mine := f.generation
		s.mu.Unlock()
		for ctx.Err() == nil {
			start := s.Now()
			w, err := s.Observer.WatchWorkloads(ctx, kind, cursor, f.selection)
			if err == nil {
				for {
					var e WorkloadEvent
					if e, err = w.Next(ctx); err != nil {
						break
					}
					cursor = e.ResourceVersion
					if e.Type == "BOOKMARK" {
						continue
					}
					s.mu.Lock()
					if f.generation != mine {
						s.mu.Unlock()
						err = value.ErrChanged
						break
					}
					ok := e.Workload != nil && valid(*e.Workload) && f.listed[kind] && (e.Type != "ADDED" || len(f.journal.byUID) < value.MaxObservedWorkloads)
					if ok {
						if old, exists := f.journal.byUID[e.Workload.UID]; exists && (old.Name != e.Workload.Name || old.Namespace.Name != e.Workload.Namespace.Name || old.Kind != kind) {
							ok = false
						}
					}
					switch {
					case !ok:
						s.resetLocked(f)
						err = value.ErrChanged
					case e.Type == "DELETED":
						if _, exists := f.journal.byUID[e.Workload.UID]; exists {
							f.journal.sequence++
						}
						delete(f.journal.byUID, e.Workload.UID)
						delete(f.journal.changes, e.Workload.UID)
					case e.Type == "ADDED" || e.Type == "MODIFIED":
						f.journal.set(*e.Workload)
					default:
						s.resetLocked(f)
						err = value.ErrChanged
					}
					s.mu.Unlock()
					if err != nil {
						break
					}
				}
				w.Close()
				if errors.Is(err, io.EOF) {
					s.mu.Lock()
					current := f.generation == mine
					if current && start.After(f.observed[kind]) {
						f.observed[kind] = start
					}
					s.mu.Unlock()
					if current {
						continue
					}
					err = value.ErrChanged
				}
			}
			if errors.Is(err, value.ErrChanged) || !pause() {
				break
			}
		}
	}
}
