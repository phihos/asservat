package configuration

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/privacy"
)

func TestRetentionMaintenanceRejectsClockRollback(t *testing.T) {
	at := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	run := retentionRun{lastObservation: at, r: RetentionReconciler{Now: func() time.Time { return at.Add(-time.Second) }}}
	if delay := run.observationDelay(); delay > time.Second {
		t.Fatal("rollback postponed the next check", delay)
	}
	if err := run.maintain(context.Background()); !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("clock rollback did not invalidate observation renewal", err)
	}
}

type observationStore struct {
	RetentionCheckpointStore
	observe func(RetentionObservation) error
}

func (s observationStore) ObserveRetention(_ context.Context, o RetentionObservation) error {
	return s.observe(o)
}

func TestObservationWindowConfirmsFreshestCoveredOriginalList(t *testing.T) {
	base := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	now := base.Add(4500 * time.Millisecond)
	watermark := 3
	confirmed := []RetentionObservation{}
	run := retentionRun{r: RetentionReconciler{Now: func() time.Time { return now }, Store: observationStore{observe: func(o RetentionObservation) error {
		v, _ := strconv.Atoi(o.List.ResourceVersion)
		if v > watermark {
			return value.ErrRetentionHistoryBehind
		}
		confirmed = append(confirmed, o)
		return nil
	}}}}
	for i := 0; i < 5; i++ {
		start := base.Add(time.Duration(i) * time.Second)
		run.pendingObservations = append(run.pendingObservations, RetentionObservation{List: PolicyList{ResourceVersion: strconv.Itoa(i), Snapshot: privacy.PolicySnapshot{ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}}, Protection: privacy.SourceProtection{ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}})
	}
	if err := run.observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(confirmed) != 1 || confirmed[0].List.ResourceVersion != "3" || !confirmed[0].List.Snapshot.ObservedAt.Equal(base.Add(3*time.Second)) || !confirmed[0].List.Snapshot.FreshUntil.Equal(base.Add(8*time.Second)) || len(run.pendingObservations) != 1 || run.pendingObservations[0].List.ResourceVersion != "4" {
		t.Fatal("did not preserve freshest covered observation", confirmed, run.pendingObservations)
	}
	watermark = 4
	now = base.Add(6 * time.Second)
	if err := run.observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(confirmed) != 2 || len(run.pendingObservations) != 0 || !confirmed[1].List.Snapshot.FreshUntil.Equal(base.Add(9*time.Second)) {
		t.Fatal("bookmark renewed deadline", confirmed)
	}
}

func TestObsoleteObservationDoesNotStopNewerPendingWork(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	run := retentionRun{r: RetentionReconciler{Now: func() time.Time { return now }, Store: observationStore{observe: func(o RetentionObservation) error {
		if o.List.ResourceVersion == "new" {
			return value.ErrRetentionHistoryBehind
		}
		return value.ErrRetentionObservationObsolete
	}}}}
	for _, rv := range []string{"old", "obsolete", "new"} {
		run.pendingObservations = append(run.pendingObservations, RetentionObservation{List: PolicyList{ResourceVersion: rv, Snapshot: privacy.PolicySnapshot{ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}, Protection: privacy.SourceProtection{ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}})
	}
	if err := run.observe(context.Background()); err != nil || len(run.pendingObservations) != 1 || run.pendingObservations[0].List.ResourceVersion != "new" {
		t.Fatal(err, run.pendingObservations)
	}
	now = now.Add(5 * time.Second)
	if err := run.observe(context.Background()); err != nil || len(run.pendingObservations) != 0 {
		t.Fatal("expired work remained", err)
	}
}
