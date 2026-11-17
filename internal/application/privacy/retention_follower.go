package privacy

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	value "asservat.local/asservat/internal/domain/privacy"
)

// RetentionEvent is one EvidenceRetentionPolicy watch event. Type is ADDED,
// MODIFIED, DELETED or BOOKMARK; Policy is set except for BOOKMARK.
type RetentionEvent struct {
	Type, ResourceVersion string
	Policy                value.ScopedPolicy
}

// RetentionWatch delivers watch events until io.EOF (server timeout) or an
// error (the follower lists again).
type RetentionWatch interface {
	Next(context.Context) (RetentionEvent, error)
	Close()
}

// RetentionSource lists and watches the policies of the hub control namespace.
type RetentionSource interface {
	ListRetentionPolicies(context.Context) ([]value.ScopedPolicy, string, error)
	WatchRetentionPolicies(context.Context, string) (RetentionWatch, error)
}

// RetentionStore keeps the current policy set and applies every new or
// changed policy to stored deadlines in the same transaction.
type RetentionStore interface {
	SyncRetentionPolicies(context.Context, []value.ScopedPolicy) error
}

// RetentionFollower applies EvidenceRetentionPolicy events to stored
// deadlines (ADR-330 D12): list, store, then watch from the list's
// resourceVersion and store the complete set after each event. A failed
// list, watch or store lists again after a backoff, so an event missed
// during an outage converges on the next list. Each rejected policy
// generation is reported once.
type RetentionFollower struct {
	Source RetentionSource
	Store  RetentionStore
	Report func(string, error)
	// Rejected reports a policy generation the follower stored as rejected.
	Rejected func(value.ScopedPolicy)
}

// retentionBackoff bounds retries against an unavailable API server or
// database; it caps at 30 seconds like client-go's reflector backoff.
var retentionBackoff = []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second}

func (f RetentionFollower) Run(ctx context.Context) {
	failures := 0
	reported := map[string]int64{}
	for ctx.Err() == nil {
		stage, progressed, err := f.follow(ctx, reported)
		if ctx.Err() != nil {
			return
		}
		// Only a watch that delivered an event or ended normally resets the
		// backoff: a list and store followed by an immediate watch failure
		// (410 Gone, malformed event) keeps backing off.
		if progressed {
			failures = 0
		}
		if f.Report != nil {
			f.Report(stage, err)
		}
		wait := retentionBackoff[min(failures, len(retentionBackoff)-1)]
		failures++
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// follow reports the failed stage and whether its watch made progress.
func (f RetentionFollower) follow(ctx context.Context, reported map[string]int64) (string, bool, error) {
	list, rv, err := f.Source.ListRetentionPolicies(ctx)
	if err != nil {
		return "list", false, err
	}
	current := map[string]value.ScopedPolicy{}
	for _, p := range list {
		current[p.Policy.Revision.UID] = p
	}
	if err = f.store(ctx, current, reported); err != nil {
		return "store", false, err
	}
	progressed := false
	for ctx.Err() == nil {
		w, err := f.Source.WatchRetentionPolicies(ctx, rv)
		if err != nil {
			return "watch", progressed, err
		}
		var events int
		rv, events, err = f.drain(ctx, w, rv, current, reported)
		w.Close()
		progressed = progressed || events > 0 || errors.Is(err, io.EOF)
		if !errors.Is(err, io.EOF) {
			return "watch", progressed, err
		}
	}
	return "", progressed, ctx.Err()
}

// drain stores the set after every policy event and returns the last
// resourceVersion and the number of stored events; io.EOF means the watch
// ended normally.
func (f RetentionFollower) drain(ctx context.Context, w RetentionWatch, rv string, current map[string]value.ScopedPolicy, reported map[string]int64) (string, int, error) {
	events := 0
	for {
		e, err := w.Next(ctx)
		if err != nil {
			return rv, events, err
		}
		rv = e.ResourceVersion
		switch e.Type {
		case "BOOKMARK":
			continue
		case "DELETED":
			delete(current, e.Policy.Policy.Revision.UID)
		default:
			current[e.Policy.Policy.Revision.UID] = e.Policy
		}
		if err = f.store(ctx, current, reported); err != nil {
			return rv, events, err
		}
		events++
	}
}

func (f RetentionFollower) store(ctx context.Context, current map[string]value.ScopedPolicy, reported map[string]int64) error {
	set := make([]value.ScopedPolicy, 0, len(current))
	for _, p := range current {
		set = append(set, p)
	}
	slices.SortFunc(set, func(a, b value.ScopedPolicy) int {
		return strings.Compare(a.Policy.Revision.UID, b.Policy.Revision.UID)
	})
	if err := f.Store.SyncRetentionPolicies(ctx, set); err != nil {
		return err
	}
	for _, p := range set {
		uid, generation := p.Policy.Revision.UID, p.Policy.Revision.Generation
		if p.Rejected != "" && reported[uid] != generation && f.Rejected != nil {
			f.Rejected(p)
		}
		reported[uid] = generation
	}
	for uid := range reported {
		if _, ok := current[uid]; !ok {
			delete(reported, uid)
		}
	}
	return nil
}
