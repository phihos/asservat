package configuration

import (
	"cmp"
	"context"
	"errors"
	"io"
	"maps"
	"slices"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// BindingReconciler accepts explicit AccessBindings and, with a namespace
// observer, namespaceMetadata PermissionSources (ADR-242) from a qualified
// Kubernetes installation into one SQL stream. A single Run owns one epoch;
// failure/cancellation suspends it. A supervisor may restart with a new epoch.
// Dependencies are ports; production composition must supply qualified readers.
type BindingReconciler struct {
	RootID  string
	Reader  PermissionReader
	Watcher BindingWatcher
	Trust   PermissionTrustReader
	Review  BootstrapReviewReader
	Store   PermissionStore
	// Namespaces observes NamespaceClusterID's namespaces for inheritance.
	// Without it every namespaceMetadata source is unavailable: its accepted
	// assignments are kept but grant nothing.
	Namespaces         NamespaceObserver
	NamespaceClusterID string
	// Guards proves a cluster's namespace admission guard for
	// admissionEnforced sources and Directory supplies the configured group
	// directory for groupID mapping (ADR-247). Without them such sources are
	// unavailable: kept, granting nothing.
	Guards    NamespaceGuardReader
	Directory GroupDirectoryReader
	// Remote reads the namespace journal of another joined cluster from its
	// connector (ADR-247). Without it namespaceMetadata sources of clusters
	// other than NamespaceClusterID are unavailable.
	Remote RemoteNamespaceReader
	// Workloads reads a cluster's connector workload journal and
	// WorkloadGuards its workload metadata guard proof (ADR-247), the hub
	// cluster's included. Without them workloadMetadata sources are
	// unavailable.
	Workloads      RemoteWorkloadReader
	WorkloadGuards WorkloadGuardReader
	Now            func() time.Time
	NewID          func() string
}

// NamespaceGuardReader proves, within its original interval, that one
// cluster's namespace metadata guard currently enforces its keys (ADR-247).
type NamespaceGuardReader interface {
	NamespaceGuard(context.Context, string) (value.NamespaceGuardProof, error)
}

// GroupDirectoryReader returns the administrator-configured stable group IDs
// of one issuer (ADR-247); it reads protected configuration, no directory.
type GroupDirectoryReader interface {
	GroupDirectory(context.Context, string) (value.GroupDirectory, error)
}

// RemoteNamespaceReader returns a joined cluster's connector namespace
// journal of keys (ADR-247): ResourceVersion is the journal ID, each
// namespace's ResourceVersion its journal version and ObservedAt the
// journal's own freshness.
type RemoteNamespaceReader interface {
	RemoteNamespaces(context.Context, string, value.NamespaceKeys) (value.NamespaceList, error)
}

// RemoteNamespaceRefresh is how often the reconciler rereads a joined
// cluster's namespace journal (ADR-247); MaxRemoteNamespaceClusters bounds
// the clusters read.
const (
	RemoteNamespaceRefresh     = 10 * time.Second
	MaxRemoteNamespaceClusters = 8
)

// RemoteWorkloadReader returns a cluster's connector workload journal of one
// selection (ADR-247), with journal versions.
type RemoteWorkloadReader interface {
	RemoteWorkloads(context.Context, string, value.WorkloadSelection) (value.WorkloadList, error)
}

// WorkloadGuardReader proves a cluster's workload metadata guard (ADR-247).
type WorkloadGuardReader interface {
	WorkloadGuard(context.Context, string) (value.NamespaceGuardProof, error)
}

// MaxWorkloadSelections bounds the workload journals the reconciler reads.
const MaxWorkloadSelections = 32

type remoteWorkloads struct {
	live       *value.WorkloadObservation
	observedAt time.Time
	fetchedAt  time.Time
}

func workloadKey(cluster string, sel value.WorkloadSelection) string {
	return cluster + "|" + value.SelectionKey(sel)
}

type remoteNamespaces struct {
	keys       value.NamespaceKeys
	live       *value.NamespaceObservation
	observedAt time.Time
	fetchedAt  time.Time
}

type bindingRun struct {
	r          BindingReconciler
	fence      value.PermissionFence
	journal    *BindingJournal
	trustUntil time.Time
	// Inheritance state (ADR-242). continuity counts namespace journals and
	// dropped transitions; a source's bases are continuous only while
	// included holds the counter value of its last accepted inclusion.
	sources         []value.Source
	sourcesComplete bool
	feed            *namespaceFeed
	namespaces      *NamespaceJournal
	continuity      int
	included        map[string]int
	lastInheritance [32]byte
	// guards and directories are the last current evidence per cluster and
	// issuer (ADR-247), refreshed before they lapse.
	guards      map[string]*value.NamespaceGuardProof
	directories map[string]*value.GroupDirectory
	// remote is the last journal read per joined cluster (ADR-247).
	remote map[string]*remoteNamespaces
	// workloads is the last workload journal read per (cluster, selection)
	// and workloadGuards the last workload guard proof per cluster.
	workloads      map[string]*remoteWorkloads
	workloadGuards map[string]*value.NamespaceGuardProof
}

// refreshWorkloads rereads, like refreshRemote, the workload journals the
// current workloadMetadata sources select.
func (s *bindingRun) refreshWorkloads(ctx context.Context) {
	if s.r.Workloads == nil || !s.sourcesComplete {
		return
	}
	type want struct {
		cluster string
		sel     value.WorkloadSelection
	}
	wanted := map[string]want{}
	for _, src := range s.sources {
		if src.Type != "workloadMetadata" || !src.Enabled || !authorization.UUID(src.ClusterID) {
			continue
		}
		if sel := WorkloadSelectionOf(src); sel.Valid() {
			wanted[workloadKey(src.ClusterID, sel)] = want{src.ClusterID, sel}
		}
	}
	keys := slices.Sorted(maps.Keys(wanted))
	// ponytail: selections beyond the bound stay unavailable.
	keys = keys[:min(len(keys), MaxWorkloadSelections)]
	now := s.r.Now()
	next := map[string]*remoteWorkloads{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, key := range keys {
		old := s.workloads[key]
		if old != nil {
			next[key] = old
			if now.Sub(old.fetchedAt) < RemoteNamespaceRefresh {
				continue
			}
		}
		w := wanted[key]
		wg.Add(1)
		go func() {
			defer wg.Done()
			call, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			l, err := s.r.Workloads.RemoteWorkloads(call, w.cluster, w.sel)
			if err != nil || l.ClusterID != w.cluster || !l.Selection.Equal(w.sel) || l.ObservedAt.After(s.r.Now().Add(time.Second)) || len(l.Workloads) > value.MaxObservedWorkloads {
				return
			}
			o := &value.WorkloadObservation{ClusterID: w.cluster, Selection: w.sel, Workloads: slices.Clone(l.Workloads)}
			slices.SortFunc(o.Workloads, func(a, b value.ObservedWorkload) int { return cmp.Compare(a.UID, b.UID) })
			for i, x := range o.Workloads {
				if !x.Valid(w.sel.Keys, true) || i > 0 && o.Workloads[i-1].UID == x.UID {
					return
				}
			}
			mu.Lock()
			next[key] = &remoteWorkloads{live: o, observedAt: l.ObservedAt, fetchedAt: now}
			mu.Unlock()
		}()
	}
	wg.Wait()
	s.workloads = next
}

// refreshRemote rereads, concurrently and within three seconds, the journals
// of the joined clusters the current sources name that are missing, have
// other keys or are older than RemoteNamespaceRefresh. A failed read keeps
// the previous journal state; its sources lapse with its ObservedAt.
func (s *bindingRun) refreshRemote(ctx context.Context) {
	if s.r.Remote == nil || !s.sourcesComplete {
		return
	}
	var clusters []string
	for _, src := range s.sources {
		if src.Type == "namespaceMetadata" && src.Enabled && src.ClusterID != s.r.NamespaceClusterID && authorization.UUID(src.ClusterID) && !slices.Contains(clusters, src.ClusterID) {
			clusters = append(clusters, src.ClusterID)
		}
	}
	slices.Sort(clusters)
	// ponytail: clusters beyond the bound stay unavailable; raise with the regional cluster cap.
	clusters = clusters[:min(len(clusters), MaxRemoteNamespaceClusters)]
	now := s.r.Now()
	next := map[string]*remoteNamespaces{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, cluster := range clusters {
		keys := SourceKeys(s.sources, cluster)
		old := s.remote[cluster]
		if old != nil && !sameKeys(old.keys, keys) {
			old = nil
		}
		if old != nil && now.Sub(old.fetchedAt) < RemoteNamespaceRefresh {
			next[cluster] = old
			continue
		}
		if old != nil {
			next[cluster] = old
		}
		if len(keys.Labels)+len(keys.Annotations) == 0 || !keys.Valid() {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			call, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			l, err := s.r.Remote.RemoteNamespaces(call, cluster, keys)
			if err != nil || l.ClusterID != cluster || !sameKeys(l.Keys, keys) || l.ObservedAt.After(s.r.Now().Add(time.Second)) {
				return
			}
			j, err := NewNamespaceJournal(l)
			if err != nil {
				return
			}
			mu.Lock()
			next[cluster] = &remoteNamespaces{keys: keys, live: j.Observation(true), observedAt: l.ObservedAt, fetchedAt: now}
			mu.Unlock()
		}()
	}
	wg.Wait()
	s.remote = next
}

func sameKeys(a, b value.NamespaceKeys) bool {
	return slices.Equal(a.Labels, b.Labels) && slices.Equal(a.Annotations, b.Annotations)
}

// refreshEvidence renews the guard proofs and group directories the current
// sources need when they are missing or about to lapse. A failure only
// leaves the evidence missing: those sources become unavailable.
func (s *bindingRun) refreshEvidence(ctx context.Context) {
	now := s.r.Now()
	if s.guards == nil {
		s.guards, s.directories = map[string]*value.NamespaceGuardProof{}, map[string]*value.GroupDirectory{}
	}
	if s.workloadGuards == nil {
		s.workloadGuards = map[string]*value.NamespaceGuardProof{}
	}
	for _, src := range s.sources {
		if src.Type != "namespaceMetadata" && src.Type != "workloadMetadata" || !src.Enabled {
			continue
		}
		if src.Type == "namespaceMetadata" && src.Protection.Mode == "admissionEnforced" && s.r.Guards != nil {
			if g := s.guards[src.ClusterID]; g == nil || g.FreshUntil.Sub(now) < 2*time.Second {
				call, cancel := context.WithTimeout(ctx, 5*time.Second)
				proof, err := s.r.Guards.NamespaceGuard(call, src.ClusterID)
				cancel()
				s.guards[src.ClusterID] = nil
				if err == nil && proof.ClusterID == src.ClusterID && proof.Current(s.r.Now()) {
					s.guards[src.ClusterID] = &proof
				}
			}
		}
		if src.Type == "workloadMetadata" && s.r.WorkloadGuards != nil {
			if g := s.workloadGuards[src.ClusterID]; g == nil || g.FreshUntil.Sub(now) < 2*time.Second {
				call, cancel := context.WithTimeout(ctx, 5*time.Second)
				proof, err := s.r.WorkloadGuards.WorkloadGuard(call, src.ClusterID)
				cancel()
				s.workloadGuards[src.ClusterID] = nil
				if err == nil && proof.ClusterID == src.ClusterID && proof.Current(s.r.Now()) {
					s.workloadGuards[src.ClusterID] = &proof
				}
			}
		}
		if issuer := src.Mapping.Issuer; src.Mapping.Mode == "groupID" && s.r.Directory != nil {
			if d := s.directories[issuer]; d == nil || d.FreshUntil.Sub(now) < 2*time.Second {
				call, cancel := context.WithTimeout(ctx, 5*time.Second)
				dir, err := s.r.Directory.GroupDirectory(call, issuer)
				cancel()
				s.directories[issuer] = nil
				if err == nil && dir.Issuer == issuer && dir.Current(s.r.Now()) {
					s.directories[issuer] = &dir
				}
			}
		}
	}
}

func (r BindingReconciler) valid() bool {
	return authorization.UUID(r.RootID) && r.Reader != nil && r.Watcher != nil && r.Trust != nil && r.Store != nil && r.Now != nil && r.NewID != nil &&
		(r.Namespaces == nil || authorization.UUID(r.NamespaceClusterID))
}
func (r BindingReconciler) trust(ctx context.Context) (PermissionTrust, error) {
	t, err := r.Trust.PermissionTrust(ctx)
	if err != nil {
		return PermissionTrust{}, err
	}
	if t.Digest == ([32]byte{}) || !identity.Fresh(t.ObservedAt, t.FreshUntil, r.Now(), 5*time.Second) {
		return PermissionTrust{}, value.ErrUnavailable
	}
	return t, nil
}
func (s *bindingRun) guardedSnapshot(ctx context.Context, first PermissionTrust) (value.Snapshot, error) {
	snapshot, err := s.r.Reader.PermissionSnapshot(ctx)
	if err != nil {
		return value.Snapshot{}, err
	}
	last, err := s.r.trust(ctx)
	if err != nil {
		return value.Snapshot{}, err
	}
	if first.Digest != s.fence.TrustDigest || last.Digest != first.Digest || !identity.Fresh(first.ObservedAt, first.FreshUntil, s.r.Now(), 5*time.Second) {
		return value.Snapshot{}, value.ErrChanged
	}
	s.trustUntil = identity.Earlier(first.FreshUntil, last.FreshUntil)
	snapshot.FreshUntil = identity.Earlier(snapshot.FreshUntil, s.trustUntil)
	return snapshot, nil
}
func (s *bindingRun) accept(ctx context.Context, refresh bool) error {
	if !s.r.Now().Before(s.trustUntil) {
		return reconcileStep("trust-expired", value.ErrUnavailable)
	}
	if err := s.journal.Constrain(s.trustUntil); err != nil {
		return reconcileStep("constrain", err)
	}
	now := s.r.Now()
	inherited := s.inheritance(now)
	b, err := s.journal.Prepare(s.fence, s.r.NewID(), now, inherited.Inheritance)
	if err != nil {
		return reconcileStep("prepare", err)
	}
	commit := func() {
		s.included, s.lastInheritance = inherited.included, inheritanceDigest(inherited)
	}
	if refresh {
		err = s.r.Store.RefreshPermissions(ctx, b)
		if err == nil {
			if err = s.journal.Refreshed(b.RequestID); err != nil {
				return reconcileStep("refreshed", err)
			}
			// The identical accepted projection holds exactly these
			// namespace versions, so the current journal continues it.
			commit()
			return nil
		}
		// Identical input may have an expired member. Accept that removal as a
		// new transition; an epoch/sequence conflict still fails in the store.
		if !errors.Is(err, value.ErrChanged) {
			return reconcileStep("store-refresh", err)
		}
	}
	accepted, err := s.r.Store.AcceptPermissions(ctx, b)
	if err != nil {
		return reconcileStep("store-accept", err)
	}
	if err = s.journal.Accepted(accepted); err != nil {
		return reconcileStep("accepted", err)
	}
	s.fence = accepted.PermissionFence
	commit()
	return nil
}
func (s *bindingRun) start(ctx context.Context) error {
	first, err := s.r.trust(ctx)
	if err != nil {
		return reconcileStep("trust", err)
	}
	s.fence, err = s.r.Store.BeginPermissions(ctx, s.r.RootID, s.r.NewID(), first.Digest)
	if err != nil {
		return reconcileStep("begin", err)
	}
	snapshot, err := s.guardedSnapshot(ctx, first)
	if err != nil {
		return reconcileStep("snapshot", err)
	}
	s.syncSources(ctx, snapshot)
	s.journal, err = NewBindingJournal(snapshot, s.r.Now())
	if err != nil {
		return reconcileStep("journal", err)
	}
	if !s.fence.Initialized && len(snapshot.Bindings) > 0 {
		if s.r.Review == nil {
			return value.ErrDenied
		}
		review, e := s.r.Review.InitialPermissionReview(ctx)
		if e != nil {
			return reconcileStep("review", e)
		}
		if err = s.journal.SetInitialReview(review, s.r.Now()); err != nil {
			return reconcileStep("review", err)
		}
	}
	if err = s.accept(ctx, false); err != nil {
		return reconcileStep("accept", err)
	}
	return nil
}

var errWatchBehind = errors.New("permission watch has not reached current complete list")

func (s *bindingRun) refresh(ctx context.Context) error {
	// Before the trust window opens: a slow connector cannot consume it.
	s.refreshRemote(ctx)
	s.refreshWorkloads(ctx)
	// Proofs last: closest to the acceptance that uses them.
	s.refreshEvidence(ctx)
	first, err := s.r.trust(ctx)
	if err != nil {
		return reconcileStep("trust", err)
	}
	snapshot, err := s.guardedSnapshot(ctx, first)
	if err != nil {
		return reconcileStep("snapshot", err)
	}
	s.syncSources(ctx, snapshot)
	if err = s.journal.Confirm(snapshot, s.r.Now()); err != nil {
		// Do not replace a journal with a newer LIST and thereby skip an
		// intermediate owner. Process queued events, then retry the full LIST.
		if !s.r.Now().Before(s.journal.until) {
			return reconcileStep("confirm-expired", value.ErrUnavailable)
		}
		return errWatchBehind
	}
	if s.fence.LeaseUntil.Sub(s.r.Now()) < 10*time.Second {
		s.fence, err = s.r.Store.RenewPermissions(ctx, s.fence)
		if err != nil {
			return reconcileStep("renew", err)
		}
	}
	if err = s.accept(ctx, true); err != nil {
		return reconcileStep("accept", err)
	}
	return nil
}

// Run keeps event delivery bounded to one queued transition and processes each
// through SQL before reading the next. Full LISTs renew deny completeness;
// bookmarks and watch traffic do not. Audit publication is an independent role:
// the store keeps new allows unavailable until its exact record is acknowledged.
func (r BindingReconciler) Run(ctx context.Context) error {
	if !r.valid() {
		return value.ErrInvalid
	}
	s := &bindingRun{r: r}
	defer func() { s.feed.stop() }()
	defer func() {
		if s.fence.Epoch != "" {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			// Failure here leaves the original <=5s permission deadline and the
			// bounded leader lease; no goroutine keeps renewing either of them.
			_ = r.Store.SuspendPermissions(cleanup, s.fence)
		}
	}()
	if err := s.start(ctx); err != nil {
		return reconcileStep("start", err)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		watch, err := r.Watcher.WatchBindings(ctx, s.journal.Cursor())
		if err != nil {
			return reconcileStep("watch", err)
		}
		err = s.consume(ctx, watch, ticker.C)
		if !errors.Is(err, io.EOF) {
			return err
		}
	}
}
func (s *bindingRun) consume(ctx context.Context, watch BindingWatch, ticks <-chan time.Time) error {
	child, cancel := context.WithCancel(ctx)
	type result struct {
		event value.BindingEvent
		err   error
	}
	queue := make(chan result, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			e, eerr := watch.Next(child)
			select {
			case queue <- result{e, eerr}:
			case <-child.Done():
				return
			}
			if eerr != nil {
				return
			}
		}
	}()
	defer func() { cancel(); watch.Close(); <-done }()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
			if err := s.refresh(ctx); err != nil && !errors.Is(err, errWatchBehind) {
				return reconcileStep("refresh", err)
			}
		case item := <-s.feedItems():
			if err := s.namespaceItem(ctx, item); err != nil {
				return reconcileStep("inherit", err)
			}
		case item := <-queue:
			if item.err != nil {
				if errors.Is(item.err, io.EOF) {
					return item.err
				}
				return reconcileStep("watch-next", item.err)
			}
			if err := s.journal.Apply(item.event); err != nil {
				return reconcileStep("apply", err)
			}
			if item.event.Type != "BOOKMARK" {
				if err := s.accept(ctx, false); err != nil {
					return reconcileStep("accept", err)
				}
			}
		}
	}
}

// reconcileStepError names the phase that stopped a permission epoch; the
// hub-worker logs it (ADR-197 runs 23a/23b: repeated stops, no cause). Labels
// compose with nested fixed steps. Error deliberately returns only the step,
// a closed word safe to log; read the cause with errors.Is and the full chain
// with FixedStep.
type reconcileStepError struct {
	step string
	err  error
}

func reconcileStep(step string, err error) error { return &reconcileStepError{step, err} }

func (e *reconcileStepError) Error() string { return e.step }
func (e *reconcileStepError) Unwrap() error { return e.err }
func (e *reconcileStepError) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}
