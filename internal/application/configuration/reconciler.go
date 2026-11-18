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
)

// BindingReconciler accepts explicit AccessBindings and, with a namespace
// observer, namespaceMetadata PermissionSources (ADR-242) from a qualified
// Kubernetes installation into one SQL stream. A single Run owns one epoch;
// failure/cancellation suspends it. A supervisor may restart with a new epoch.
// Dependencies are ports; production composition must supply qualified readers.
type BindingReconciler struct {
	RootID string
	// Issuer is the installation's issuer: subjects and mappings that omit
	// an issuer use it (ADR-335 D4).
	Issuer  string
	Reader  PermissionReader
	Watcher BindingWatcher
	Trust   PermissionTrustReader
	Store   PermissionStore
	// Namespaces observes NamespaceClusterID's namespaces for inheritance.
	// Without it every namespaceMetadata source is unavailable: its accepted
	// assignments are kept but grant nothing.
	Namespaces         NamespaceObserver
	NamespaceClusterID string
	// Remote reads the namespace journal of another joined cluster from its
	// connector (ADR-247). Without it namespaceMetadata sources of clusters
	// other than NamespaceClusterID are unavailable.
	Remote RemoteNamespaceReader
	// Workloads reads a cluster's connector workload journal (ADR-247).
	// Without it workloadMetadata sources are unavailable.
	Workloads RemoteWorkloadReader
	// RemoteBindings reads the AccessBinding deliveries of workload
	// clusters joined with mode: cluster (ADR-329). Without it their
	// AccessBindings grant and deny nothing.
	RemoteBindings RemoteBindingReader
	// RemoteBindingChanges signals a changed stored delivery (PostgreSQL
	// LISTEN/NOTIFY); deliveries are reread only on a signal and at start.
	RemoteBindingChanges <-chan struct{}
	RegisteredClusters   []string // Helm registrations that must report both binding kinds before use.
	WatchConfiguration   func(context.Context, string, string) (SettingsWatch, error)
	ReadSources          func(context.Context) (value.Snapshot, error)
	Now                  func() time.Time
	NewID                func() string
}

// SettingsWatch coalesces changes and reports loss of the observed history
// independently, even while a replacement LIST is in progress.
type SettingsWatch struct{ Changed, Lost <-chan struct{} }

type sourceRead struct {
	snapshot value.Snapshot
	watch    SettingsWatch
}

// RemoteNamespaceReader returns a joined cluster's connector namespace
// journal of keys (ADR-247): ResourceVersion is the journal ID, each
// namespace's ResourceVersion its journal version and ObservedAt the
// journal's own freshness.
type RemoteNamespaceReader interface {
	RemoteNamespaces(context.Context, string, value.NamespaceKeys) (value.NamespaceList, error)
}

// RemoteNamespaceRefresh is how often the reconciler rereads a joined
// cluster's namespace journal (ADR-247).
const RemoteNamespaceRefresh = 10 * time.Second

// RemoteWorkloadReader returns a cluster's connector workload journal of one
// selection (ADR-247), with journal versions.
type RemoteWorkloadReader interface {
	RemoteWorkloads(context.Context, string, value.WorkloadSelection) (value.WorkloadList, error)
}

// RemoteBindingReader returns the latest AccessBinding delivery of each
// joined workload cluster (ADR-329), attributed by the hub to the
// delivering connector's authenticated cluster.
type RemoteBindingReader interface {
	RemoteBindings(context.Context) ([]value.RemoteBindings, error)
}

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
	r                               BindingReconciler
	fence                           value.PermissionFence
	trust                           PermissionTrust
	journal                         *BindingJournal
	nextExpiry                      time.Time
	clusterSettings, sourceSettings SettingsWatch
	readingSources                  <-chan sourceRead
	firstWatch                      BindingWatch
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
	// remote is the last journal read per joined cluster (ADR-247).
	remote map[string]*remoteNamespaces
	// workloads is the last workload journal read per (cluster, selection).
	workloads map[string]*remoteWorkloads
	// remoteBindings is the last valid delivery per joined cluster (ADR-329).
	remoteBindings map[string]value.RemoteBindings
	// clusterBindings are the last listed ClusterAccessBindings.
	clusterBindings []value.Binding
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
	now := s.r.Now()
	next := map[string]*remoteWorkloads{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, key := range keys {
		old := s.workloads[key]
		if old != nil {
			mu.Lock()
			next[key] = old
			mu.Unlock()
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
			if err != nil || l.ClusterID != w.cluster || !l.Selection.Equal(w.sel) || l.ObservedAt.After(s.r.Now().Add(time.Second)) {
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
// ClusterAccessBinding selectors are observed even while the source list is
// incomplete.
func (s *bindingRun) refreshRemote(ctx context.Context) {
	if s.r.Remote == nil {
		return
	}
	sources := s.sources
	if !s.sourcesComplete {
		sources = nil
	}
	var clusters []string
	for _, src := range sources {
		if src.Type == "namespaceMetadata" && src.Enabled && src.ClusterID != s.r.NamespaceClusterID && authorization.UUID(src.ClusterID) && !slices.Contains(clusters, src.ClusterID) {
			clusters = append(clusters, src.ClusterID)
		}
	}
	for _, b := range s.clusterBindings {
		if len(b.NamespaceSelector) > 0 && b.Scope.ClusterID != s.r.NamespaceClusterID && !slices.Contains(clusters, b.Scope.ClusterID) {
			clusters = append(clusters, b.Scope.ClusterID)
		}
	}
	slices.Sort(clusters)
	now := s.r.Now()
	next := map[string]*remoteNamespaces{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, cluster := range clusters {
		keys := namespaceKeys(sources, s.clusterBindings, cluster)
		old := s.remote[cluster]
		if old != nil && !sameKeys(old.keys, keys) {
			old = nil
		}
		if old != nil && now.Sub(old.fetchedAt) < RemoteNamespaceRefresh {
			mu.Lock()
			next[cluster] = old
			mu.Unlock()
			continue
		}
		if old != nil {
			mu.Lock()
			next[cluster] = old
			mu.Unlock()
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

func (r BindingReconciler) valid() bool {
	return authorization.UUID(r.RootID) && r.Reader != nil && r.Watcher != nil && r.Trust != nil && r.Store != nil && r.Now != nil && r.NewID != nil && (r.ReadSources == nil || r.WatchConfiguration != nil) &&
		(r.Namespaces == nil || authorization.UUID(r.NamespaceClusterID))
}
func (r BindingReconciler) trust(ctx context.Context) (PermissionTrust, error) {
	t, err := r.Trust.PermissionTrust(ctx)
	if err != nil {
		return PermissionTrust{}, err
	}
	if t.Digest == ([32]byte{}) || !value.PermissionObservationCurrent(t.ObservedAt, t.FreshUntil, r.Now()) {
		return PermissionTrust{}, value.ErrUnavailable
	}
	return t, nil
}
func (s *bindingRun) checkTrust(ctx context.Context) (PermissionTrust, error) {
	t, err := s.r.trust(ctx)
	if err != nil {
		return PermissionTrust{}, err
	}
	if t.Digest != s.fence.TrustDigest {
		return PermissionTrust{}, value.ErrChanged
	}
	s.trust = t
	return t, nil
}

// Bound a blocking baseline or refresh by its actual authority. Watch streams
// opened at the returned cursors belong to the epoch's longer-lived context.
func (s *bindingRun) listContext(ctx context.Context) (context.Context, context.CancelFunc) {
	until := value.PermissionDeadline(s.fence.LeaseUntil, s.trust.FreshUntil)
	if until.IsZero() {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, until.Sub(s.r.Now()))
}

func (s *bindingRun) guardedSnapshot(ctx context.Context) (value.Snapshot, error) {
	read, cancel := s.listContext(ctx)
	snapshot, err := s.r.Reader.PermissionSnapshot(read)
	cancel()
	if err != nil {
		return value.Snapshot{}, err
	}
	if watch := s.r.WatchConfiguration; watch != nil {
		if s.clusterSettings.Changed == nil {
			s.clusterSettings, err = watch(ctx, "clusteraccessbindings", snapshot.ClusterBindingResourceVersion)
			if err != nil {
				return value.Snapshot{}, err
			}
		}
	}
	if s.r.ReadSources != nil {
		// The mandatory snapshot joins the latest independent source state.
		snapshot.Sources, snapshot.SourcesComplete = s.sources, s.sourcesComplete
	}
	// A finite trust observation is checked again after a blocking LIST.
	// Platform trust without an expiry is established once per epoch.
	if !s.trust.FreshUntil.IsZero() {
		if _, err := s.checkTrust(ctx); err != nil {
			return value.Snapshot{}, err
		}
	}
	snapshot.FreshUntil = value.PermissionDeadline(snapshot.FreshUntil, s.trust.FreshUntil)
	return snapshot, nil
}
func (s *bindingRun) accept(ctx context.Context, onlyChangedInheritance bool) error {
	if err := s.observeTrust(ctx); err != nil {
		return err
	}
	return s.commit(ctx, onlyChangedInheritance)
}
func (s *bindingRun) observeTrust(ctx context.Context) error {
	if !s.journal.until.IsZero() && !s.r.Now().Before(s.journal.until) {
		if s.trust.FreshUntil.IsZero() {
			// The finite bound came from the source itself. Relist it.
			return value.ErrChanged
		}
		t, err := s.checkTrust(ctx)
		if err != nil {
			return err
		}
		s.journal.observed, s.journal.until = t.ObservedAt, t.FreshUntil
	}
	return nil
}
func (s *bindingRun) commit(ctx context.Context, onlyChangedInheritance bool) error {
	select {
	case <-s.clusterSettings.Lost:
		return value.ErrChanged
	default:
	}
	now := s.r.Now()
	inherited := s.inheritance(now)
	derived := inheritanceDigest(inherited)
	if onlyChangedInheritance && derived == s.lastInheritance {
		return nil
	}
	b, err := s.journal.Prepare(s.fence, s.r.NewID(), now, inherited.Inheritance)
	if err != nil {
		return reconcileStep("prepare", err)
	}
	accepted, err := s.r.Store.AcceptPermissions(ctx, b)
	if err != nil {
		return reconcileStep("store-accept", err)
	}
	if err = s.journal.Accepted(accepted); err != nil {
		return reconcileStep("accepted", err)
	}
	s.fence = accepted.PermissionFence
	s.included, s.lastInheritance = inherited.included, derived
	s.nextExpiry = time.Time{}
	consider := func(at time.Time) {
		if at.After(now) && (s.nextExpiry.IsZero() || at.Before(s.nextExpiry)) {
			s.nextExpiry = at
		}
	}
	for _, basis := range b.Bases {
		consider(basis.NotAfter)
	}
	for _, r := range s.remote {
		consider(r.observedAt.Add(authorization.PermissionObservationInterval))
	}
	for _, w := range s.workloads {
		consider(w.observedAt.Add(authorization.PermissionObservationInterval))
	}

	return nil
}
func (s *bindingRun) start(ctx context.Context) error {
	first, err := s.r.trust(ctx)
	if err != nil {
		return reconcileStep("trust", err)
	}
	s.trust = first
	s.fence, err = s.r.Store.BeginPermissions(ctx, s.r.RootID, s.r.NewID(), first.Digest)
	if err != nil {
		return reconcileStep("begin", err)
	}
	snapshot, err := s.guardedSnapshot(ctx)
	if err != nil {
		return reconcileStep("snapshot", err)
	}
	s.syncSources(ctx, snapshot)
	s.refreshRemote(ctx)
	s.refreshWorkloads(ctx)
	s.journal, err = NewBindingJournal(snapshot, s.r.Now())
	if err != nil {
		return reconcileStep("journal", err)
	}
	s.journal.Issuer = s.r.Issuer
	// The joined clusters' stored deliveries, before the first acceptance
	// (ADR-329): later changes arrive as RemoteBindingChanges.
	if _, err := s.refreshRemoteBindings(ctx); err != nil {
		return err
	}
	s.firstWatch, err = s.r.Watcher.WatchBindings(ctx, s.journal.Cursor())
	if err != nil {
		return reconcileStep("watch", err)
	}
	s.readSources(ctx)
	if err = s.commit(ctx, false); err != nil {
		s.firstWatch.Close()
		return reconcileStep("accept", err)
	}
	return nil
}

func (s *bindingRun) refreshClusterBindings(ctx context.Context) error {
	read, cancel := s.listContext(ctx)
	snapshot, err := s.r.Reader.ClusterAccessBindings(read)
	cancel()
	if err != nil {
		return err
	}
	if snapshot.ClusterID != s.journal.cluster || !value.PermissionObservationCurrent(snapshot.ObservedAt, snapshot.FreshUntil, s.r.Now()) {
		return value.ErrUnavailable
	}
	snapshot.Sources, snapshot.SourcesComplete = s.sources, s.sourcesComplete
	s.syncSources(ctx, snapshot)
	s.refreshRemote(ctx)
	s.refreshWorkloads(ctx)
	if err = s.observeTrust(ctx); err != nil {
		return err
	}
	s.journal.until = value.PermissionDeadline(s.journal.until, snapshot.FreshUntil)
	return s.commit(ctx, true)
}

// Run processes ordered watch transitions, database notifications and original
// binding expirations. The live epoch renews its lease separately from changes.
// Permission changes and their audit become visible at the same commit.
// PermissionEpochResult is a completed run's scheduling result, never current
// permission authority. Suspended is true only after exact owned-epoch
// suspension was acknowledged and all original watch/feed children joined.
type PermissionEpochResult struct {
	Err       error
	Suspended bool
}

// Run preserves the original error-only caller contract.
func (r BindingReconciler) Run(ctx context.Context) error {
	return r.RunEpoch(ctx).Err
}

// RunEpoch lets the existing supervisor avoid waiting for a lease that this
// completed run positively ended. A successor still reproves all source facts.
func (r BindingReconciler) RunEpoch(ctx context.Context) PermissionEpochResult {
	err, suspended := r.runEpoch(ctx)
	return PermissionEpochResult{Err: err, Suspended: suspended && ctx.Err() == nil}
}

func (r BindingReconciler) runEpoch(ctx context.Context) (err error, suspended bool) {
	if !r.valid() {
		return value.ErrInvalid, false
	}
	s := &bindingRun{r: r}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { s.feed.stop() }()
	defer func() {
		if s.fence.Epoch != "" {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			// Failure here leaves the original <=5s permission deadline and the
			// bounded leader lease; no goroutine keeps renewing either of them.
			suspended = r.Store.SuspendPermissions(cleanup, s.fence) == nil
		}
	}()
	if err := s.start(ctx); err != nil {
		return reconcileStep("start", err), false
	}
	// The live writer renews its 30-second database lease with ten seconds
	// left. Idle renewal never enumerates or hashes the accepted projection.
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	watch := s.firstWatch
	for {
		err = s.consume(ctx, watch, ticker.C)
		if !errors.Is(err, io.EOF) {
			return err, false
		}
		watch, err = r.Watcher.WatchBindings(ctx, s.journal.Cursor())
		if err != nil {
			return reconcileStep("watch", err), false
		}
	}
}

// At most one optional LIST/open is in flight. Its failure withdraws only
// source-based permission and retries at the next existing lease renewal.
func (s *bindingRun) readSources(ctx context.Context) {
	if s.r.ReadSources == nil || s.readingSources != nil {
		return
	}
	result := make(chan sourceRead, 1)
	s.readingSources = result
	watch := s.sourceSettings
	read, cancel := s.listContext(ctx)
	go func() {
		snapshot, err := s.r.ReadSources(read)
		cancel()
		if err == nil && watch.Changed == nil {
			watch, err = s.r.WatchConfiguration(ctx, "permissionsources", snapshot.SourceResourceVersion)
		}
		if err != nil {
			snapshot = value.Snapshot{}
		}
		result <- sourceRead{snapshot, watch}
	}()
}
func (s *bindingRun) sourceSnapshot(ctx context.Context, snapshot value.Snapshot) error {
	snapshot.ClusterBindings = s.clusterBindings
	s.syncSources(ctx, snapshot)
	s.refreshRemote(ctx)
	s.refreshWorkloads(ctx)
	return s.accept(ctx, true)
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
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		var expires <-chan time.Time
		if !s.nextExpiry.IsZero() {
			wait := s.nextExpiry.Sub(s.r.Now())
			if timer == nil {
				timer = time.NewTimer(wait)
			} else {
				timer.Reset(wait)
			}
			expires = timer.C
		}
		var sourceChanges <-chan struct{}
		if s.readingSources == nil {
			sourceChanges = s.sourceSettings.Changed
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
			fence, err := s.r.Store.RenewPermissions(ctx, s.fence)
			if err != nil {
				return reconcileStep("renew", err)
			}
			s.fence = fence
			// A failed PermissionSource LIST carries no change event when
			// Kubernetes recovers. Retry it at the next lease renewal.
			if !s.sourcesComplete {
				s.readSources(ctx)
			}
		case <-expires:
			s.refreshRemote(ctx)
			s.refreshWorkloads(ctx)
			if err := s.accept(ctx, false); err != nil {
				return reconcileStep("expiry", err)
			}
		case <-s.clusterSettings.Lost:
			return reconcileStep("cluster-binding-watch", value.ErrChanged)
		case <-s.clusterSettings.Changed:
			select {
			case <-s.clusterSettings.Lost:
				return reconcileStep("cluster-binding-watch", value.ErrChanged)
			default:
			}
			if err := s.refreshClusterBindings(ctx); err != nil {
				return reconcileStep("refresh", err)
			}
		case <-s.sourceSettings.Lost:
			s.sourceSettings = SettingsWatch{}
			// A pending result stays attached to its original watch.
			if err := s.sourceSnapshot(ctx, value.Snapshot{}); err != nil {
				return reconcileStep("source-watch", err)
			}
			s.readSources(ctx)
		case <-sourceChanges:
			s.readSources(ctx)
		case result := <-s.readingSources:
			s.readingSources = nil
			select {
			case <-result.watch.Lost:
				if s.sourceSettings.Changed == nil {
					s.readSources(ctx)
				}
				continue
			default:
			}
			s.sourceSettings = result.watch
			if err := s.sourceSnapshot(ctx, result.snapshot); err != nil {
				return reconcileStep("sources", err)
			}
		case <-s.r.RemoteBindingChanges:
			// ADR-329: a stored delivery changed (or the notification
			// connection was re-established): reread and accept.
			changed, err := s.refreshRemoteBindings(ctx)
			if err != nil {
				return err
			}
			if !changed {
				continue
			}
			if err := s.accept(ctx, false); err != nil {
				return reconcileStep("accept", err)
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
			if item.event.Type != "BOOKMARK" && !s.journal.accepted {
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
