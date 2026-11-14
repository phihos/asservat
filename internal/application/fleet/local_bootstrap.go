package fleet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// InstallationEnrollmentAuthorizer authorizes the combined-mode connector's
// own bootstrap as the installation itself from the current protected fleet
// administration; it resolves no token.
type InstallationEnrollmentAuthorizer struct {
	Settings AdministrationReader
	Now      func() time.Time
}

func (a InstallationEnrollmentAuthorizer) AuthorizeEnrollment(ctx context.Context, _ string, profile string) (value.EnrollmentAuthority, error) {
	if a.Settings == nil || a.Now == nil {
		return value.EnrollmentAuthority{}, value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	settings, err := a.Settings.FleetAdministration(ctx)
	if err != nil {
		return value.EnrollmentAuthority{}, err
	}
	if ctx.Err() != nil {
		return value.EnrollmentAuthority{}, value.ErrUnavailable
	}
	return value.AuthorizeInstallationEnrollment(settings, profile, a.Now())
}

// BootstrapEnvelopes reads an issued slot's one-use record from the channel.
type BootstrapEnvelopes interface {
	ReadBootstrapEnvelope(context.Context, string) (value.BootstrapEnvelope, error)
}

// LocalBootstrapRecords stores the record where the local connector reads it;
// CheckBootstrapRecord reports whether that place exists.
type LocalBootstrapRecords interface {
	CheckBootstrapRecord(context.Context) error
	WriteBootstrapRecord(context.Context, value.BootstrapEnvelope) error
}

// LocalClusterBootstrap issues the combined-mode connector's bootstrap for
// the generated local binding through the audited BootstrapIssuer (its
// Authority is an InstallationEnrollmentAuthorizer and its Reservations
// reserve only the fixed local peer) and writes the record for the
// connector. A slot that expires without an activated enrollment (unclaimed,
// or claimed by an enrollment that failed) is replaced by a new one.
type LocalClusterBootstrap struct {
	Issuer          BootstrapIssuer
	Envelopes       BootstrapEnvelopes
	Records         LocalBootstrapRecords
	Binding         value.PeerBinding
	DeliveryProfile string
}

// The local slot's display values in the issue audit.
const localDisplayName, localRegion = "hub cluster", "local"

// localKey is the request idempotency key of one slot attempt. It is reused
// for retries for five minutes (one slot lifetime) and then replaced, so a
// retry resumes its own live slot and never collides with an expired one.
type localKey struct {
	digest  artifact.Digest
	created time.Time
}

func (l LocalClusterBootstrap) key(k *localKey, now time.Time) (artifact.Digest, error) {
	if k.created.IsZero() || now.Sub(k.created) >= 5*time.Minute {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return artifact.Digest{}, value.ErrUnavailable
		}
		k.digest, k.created = sha256.Sum256(append([]byte("asservat-local-bootstrap-request/v1\x00"), raw[:]...)), now
	}
	return k.digest, nil
}

// issue reserves or resumes the local slot, completes its audited issuance
// and writes the record; it returns the slot's expiry.
func (l LocalClusterBootstrap) issue(ctx context.Context, key artifact.Digest) (time.Time, error) {
	if l.Envelopes == nil || l.Records == nil || l.Issuer.Now == nil || !l.Binding.Valid() || l.Binding.Role != value.ConnectorPeer {
		return time.Time{}, value.ErrUnavailable
	}
	intent, err := l.Issuer.Issue(ctx, "", BootstrapInput{KeyDigest: key, DisplayName: localDisplayName, Region: localRegion, DeliveryProfile: l.DeliveryProfile})
	if err != nil {
		return time.Time{}, err
	}
	if intent.Slot.Binding != l.Binding {
		return time.Time{}, &BootstrapIssueStage{"binding", value.ErrDenied}
	}
	envelope, err := l.Envelopes.ReadBootstrapEnvelope(ctx, intent.Slot.ID)
	defer func() { envelope.Secret = "" }()
	if err != nil {
		return time.Time{}, &BootstrapIssueStage{"envelope", err}
	}
	if envelope.Binding != l.Binding || envelope.BootstrapID != intent.Slot.ID || !envelope.NotAfter.Equal(intent.Slot.NotAfter) {
		return time.Time{}, &BootstrapIssueStage{"envelope", value.ErrDenied}
	}
	if err = l.Records.WriteBootstrapRecord(ctx, envelope); err != nil {
		return time.Time{}, &BootstrapIssueStage{"record-secret", err}
	}
	return intent.Slot.NotAfter, nil
}

// Run keeps one live record for the local connector until its enrollment
// is activated; a claimed slot still in progress reports pending. A slot is reserved only while the record Secret exists (the chart
// renders it with the connector), and each replacement of a slot that expired
// unactivated waits longer (5 minutes doubling to an hour), so a connector that
// is down spends the administration's bootstrap history slowly. report
// receives fixed outcome words only.
func (l LocalClusterBootstrap) Run(ctx context.Context, report func(string)) error {
	var k localKey
	var gap time.Duration
	for {
		wait := 15 * time.Second
		if l.Records == nil || l.Records.CheckBootstrapRecord(ctx) != nil {
			report("no-record-secret")
			wait = time.Minute
		} else if key, err := l.key(&k, l.Issuer.Now()); err == nil {
			var notAfter time.Time
			notAfter, err = l.issue(ctx, key)
			switch {
			case err == nil:
				report("issued")
				wait = time.Until(notAfter) + time.Second + gap
				gap = min(max(2*gap, 5*time.Minute), time.Hour)
			case errors.Is(err, value.ErrLocalBootstrapConsumed):
				report("enrolled")
				return nil
			case errors.Is(err, value.ErrPending):
				report("pending")
			default:
				report("not-issued: " + localIssueCause(err))
			}
		}
		timer := time.NewTimer(max(wait, time.Second))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// localIssueCause is the failing stage and a closed cause class, never
// dependency error text: "reserve/denied".
func localIssueCause(err error) string {
	stage := "unknown"
	var s *BootstrapIssueStage
	if errors.As(err, &s) {
		stage = s.Stage
	}
	for _, c := range []struct {
		err  error
		word string
	}{{value.ErrDenied, "denied"}, {value.ErrCapacity, "capacity"}, {value.ErrConflict, "conflict"}, {value.ErrInvalid, "invalid"}, {value.ErrUnavailable, "unavailable"},
		{context.Canceled, "cancelled"}, {context.DeadlineExceeded, "deadline"}} {
		if errors.Is(err, c.err) {
			return stage + "/" + c.word
		}
	}
	return stage + "/other"
}
