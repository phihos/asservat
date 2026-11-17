package privacy

import (
	"context"
	"errors"
	"io"
	"slices"
	"testing"

	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

func followerPolicy(uid string) value.ScopedPolicy {
	return value.ScopedPolicy{Name: uid, Policy: value.Policy{Revision: identity.Revision{UID: uid, Generation: 1}}}
}

type followerWatch struct {
	events []RetentionEvent
	end    error
}

func (w *followerWatch) Next(context.Context) (RetentionEvent, error) {
	if len(w.events) == 0 {
		return RetentionEvent{}, w.end
	}
	e := w.events[0]
	w.events = w.events[1:]
	return e, nil
}
func (w *followerWatch) Close() {}

type followerFixture struct {
	lists   int
	watches []string
	queue   []*followerWatch
	stored  [][]string
	cancel  context.CancelFunc
}

func (f *followerFixture) ListRetentionPolicies(context.Context) ([]value.ScopedPolicy, string, error) {
	f.lists++
	if f.lists > 1 {
		f.cancel()
		return nil, "", errors.New("stop")
	}
	return []value.ScopedPolicy{followerPolicy("a")}, "10", nil
}
func (f *followerFixture) WatchRetentionPolicies(_ context.Context, rv string) (RetentionWatch, error) {
	f.watches = append(f.watches, rv)
	w := f.queue[0]
	f.queue = f.queue[1:]
	return w, nil
}
func (f *followerFixture) SyncRetentionPolicies(_ context.Context, set []value.ScopedPolicy) error {
	var uids []string
	for _, p := range set {
		uids = append(uids, p.Policy.Revision.UID)
	}
	f.stored = append(f.stored, uids)
	return nil
}

// List stores the set; each policy event stores the complete set; EOF
// re-watches from the last resourceVersion; a watch error lists again.
func TestRetentionFollowerAppliesEventsToCompleteSet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &followerFixture{cancel: cancel, queue: []*followerWatch{
		{events: []RetentionEvent{{Type: "ADDED", ResourceVersion: "11", Policy: followerPolicy("b")}, {Type: "BOOKMARK", ResourceVersion: "12"}}, end: io.EOF},
		{events: []RetentionEvent{{Type: "MODIFIED", ResourceVersion: "13", Policy: followerPolicy("a")}, {Type: "DELETED", ResourceVersion: "14", Policy: followerPolicy("b")}}, end: errors.New("gone")},
	}}
	RetentionFollower{Source: f, Store: f}.Run(ctx)
	want := [][]string{{"a"}, {"a", "b"}, {"a", "b"}, {"a"}}
	if f.lists != 2 || !slices.Equal(f.watches, []string{"10", "12"}) || len(f.stored) != len(want) {
		t.Fatal("follow sequence", f.lists, f.watches, f.stored)
	}
	for i := range want {
		if !slices.Equal(f.stored[i], want[i]) {
			t.Fatal("stored set", i, f.stored)
		}
	}
}

// Only a watch that delivered an event or ended normally counts as
// progress, so an immediately failing watch keeps backing off.
func TestRetentionFollowerProgressNeedsAWatchEvent(t *testing.T) {
	for name, c := range map[string]struct {
		watch *followerWatch
		want  bool
	}{
		"immediate-error":  {&followerWatch{end: errors.New("gone")}, false},
		"event-then-error": {&followerWatch{events: []RetentionEvent{{Type: "ADDED", ResourceVersion: "11", Policy: followerPolicy("b")}}, end: errors.New("gone")}, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := &followerFixture{cancel: func() {}, queue: []*followerWatch{c.watch}}
			if _, progressed, err := (RetentionFollower{Source: f, Store: f}).follow(context.Background(), map[string]int64{}); err == nil || progressed != c.want {
				t.Fatal(progressed, err)
			}
		})
	}
}

// A rejected policy generation is reported once; a new generation again.
func TestRetentionFollowerReportsEachRejectedGenerationOnce(t *testing.T) {
	bad := followerPolicy("bad")
	bad.Rejected = value.RejectedSpec
	var got []int64
	f := &followerFixture{}
	r := RetentionFollower{Store: f, Rejected: func(p value.ScopedPolicy) { got = append(got, p.Policy.Revision.Generation) }}
	reported := map[string]int64{}
	current := map[string]value.ScopedPolicy{"bad": bad}
	for _, generation := range []int64{1, 1, 2} {
		bad.Policy.Revision.Generation = generation
		current["bad"] = bad
		if err := r.store(context.Background(), current, reported); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(got, []int64{1, 2}) {
		t.Fatal(got)
	}
}
