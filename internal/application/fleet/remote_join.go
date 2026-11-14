package fleet

import (
	"context"
	"errors"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// RemoteJoinRecords is the hub-side join Secret of one remote workload
// cluster (mode=cluster). Present reports whether the Secret exists and
// brings its public join values (IDs, offer, capabilities) up to date,
// keeping any record; Create writes it with those values and, when issued,
// its bootstrap record.
type RemoteJoinRecords interface {
	Present(context.Context) (bool, error)
	Create(context.Context, *value.BootstrapEnvelope) error
	// Changed blocks until the Secret changes or is deleted after the last
	// Present or Create, or the watch ends; the caller then checks again.
	Changed(context.Context) error
}

// RemoteClusterJoin issues a remote cluster's bootstrap through the same
// audited pipeline as the combined-mode connector (LocalClusterBootstrap) and
// delivers it in a join Secret the operator copies to that cluster. A record
// is issued only when the Secret is (re)created: deleting it asks for a fresh
// five-minute record, and an expired unclaimed record spends no further
// bootstrap history on its own. After the claim, a recreated Secret carries
// the public join values without a record.
type RemoteClusterJoin struct {
	Bootstrap LocalClusterBootstrap
	Records   RemoteJoinRecords
}

// Run checks the join Secret once and again whenever a watch reports that it
// changed or was deleted (ADR-330 D1), until ctx ends. Only a failed read or
// watch waits a fixed retry delay. report receives fixed outcome words only.
func (r RemoteClusterJoin) Run(ctx context.Context, report func(string)) error {
	if r.Records == nil {
		return value.ErrUnavailable
	}
	var k localKey
	for {
		exists, err := r.Records.Present(ctx)
		switch {
		case err != nil:
			report("not-read")
		case !exists:
			report(r.create(ctx, &k))
		}
		if err == nil {
			err = r.Records.Changed(ctx)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			timer := time.NewTimer(remoteJoinRetry)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
}

// remoteJoinRetry spaces retries after a failed read or watch only.
var remoteJoinRetry = 5 * time.Second

// create issues (or, within the same five-minute key, resumes) the slot and
// creates the Secret with its record; a claimed slot creates it without one.
func (r RemoteClusterJoin) create(ctx context.Context, k *localKey) string {
	l := r.Bootstrap
	if l.Issuer.Now == nil {
		return "not-issued: inputs/unavailable"
	}
	key, err := l.key(k, l.Issuer.Now())
	if err != nil {
		return "not-issued: key/unavailable"
	}
	envelope, err := l.envelope(ctx, key)
	defer func() { envelope.Secret = "" }()
	switch {
	case errors.Is(err, value.ErrLocalBootstrapConsumed):
		if r.Records.Create(ctx, nil) != nil {
			return "claimed: not-written"
		}
		return "claimed: written"
	case err != nil:
		return "not-issued: " + localIssueCause(err)
	}
	if r.Records.Create(ctx, &envelope) != nil {
		return "issued: not-written"
	}
	return "issued"
}
