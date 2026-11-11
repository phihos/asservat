package privacy

import (
	"context"
	"errors"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/privacy"
)

type erasureStatusReadFunc func(context.Context, value.ProcessingAuthority, string) (value.ProcessingErasureStatus, error)

func (f erasureStatusReadFunc) ReadProcessingErasureStatus(ctx context.Context, a value.ProcessingAuthority, id string) (value.ProcessingErasureStatus, error) {
	return f(ctx, a, id)
}

func TestProcessingErasureStatusPreservesOneCurrentOperatorObservation(t *testing.T) {
	for _, name := range []string{"allowed", "malformed-id", "ordinary-reader", "unknown", "changed-result", "post-read-role-loss", "post-read-expiry"} {
		t.Run(name, func(t *testing.T) {
			f, changes, _ := newProcessingFixture(t)
			requestID := processingID(22)
			wantUntil := f.now.Add(2 * time.Second)
			reads := 0
			reader := erasureStatusReadFunc(func(_ context.Context, authority value.ProcessingAuthority, id string) (value.ProcessingErasureStatus, error) {
				reads++
				if id != requestID || !authority.Valid(f.now) {
					t.Fatal("status reader received a different request or invalid authority")
				}
				out := value.ProcessingErasureStatus{
					RequestID: id, ArtifactID: processingID(23), AcceptedAt: f.now.Add(-time.Minute),
					AccessUntil: f.now.Add(-2 * time.Minute), DeleteBy: f.now.Add(time.Hour), EffectiveDeleteBy: f.now.Add(time.Hour),
					AuditState: value.ProcessingErasureAuditAcknowledged, DeletionState: value.ProcessingErasureDeletionPending,
					ObservedAt: authority.ObservedAt, ValidUntil: authority.ValidUntil,
				}
				switch name {
				case "allowed":
					f.i.ValidUntil = wantUntil
				case "unknown":
					return value.ProcessingErasureStatus{}, value.ErrUnavailable
				case "changed-result":
					out.RequestID = processingID(24)
				case "post-read-role-loss":
					f.i.Groups = nil
				case "post-read-expiry":
					f.now = authority.ValidUntil
				}
				return out, nil
			})
			s := ProcessingErasureStatus{RootID: changes.RootID, InstallationID: changes.InstallationID, Policies: f, Recovery: f, Status: reader, Now: changes.Now}
			switch name {
			case "malformed-id":
				requestID = "not-a-uuid"
			case "ordinary-reader":
				f.i.Groups = nil
			}
			out, err := s.Get(t.Context(), f, requestID)
			if name == "allowed" {
				if err != nil || !out.Valid(requestID, f.now) || !out.ValidUntil.Equal(wantUntil) ||
					reads != 1 || f.policyObservations != 1 || f.recoveryObservations != 1 {
					t.Fatal("status changed its request identity or original observation", out, err, reads, f.policyObservations, f.recoveryObservations)
				}
				return
			}
			if !errors.Is(err, value.ErrUnavailable) || out != (value.ProcessingErasureStatus{}) {
				t.Fatal("status disclosed outside its request or authority", out, err)
			}
			if (name == "malformed-id" || name == "ordinary-reader") && reads != 0 {
				t.Fatal("status lookup preceded authorization")
			}
		})
	}
}
