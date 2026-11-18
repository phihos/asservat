package fleet

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type ownerLedgerFake struct {
	observe func(context.Context, value.OwnerConfigurationObservation) error
	fence   func(context.Context, time.Time) error
}

func (s ownerLedgerFake) ObserveOwnerConfiguration(ctx context.Context, o value.OwnerConfigurationObservation) error {
	return s.observe(ctx, o)
}
func (s ownerLedgerFake) FenceOwnerConfiguration(ctx context.Context, at time.Time) error {
	return s.fence(ctx, at)
}

func TestOwnerConfigurationObserve(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	for _, mode := range []string{"normal", "missing", "expired", "cancelled", "conflict", "source-deadline", "caller-deadline"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			c := value.OwnerConfiguration{Pool: value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "hub", ServiceUID: id, Deployment: "hub", DeploymentUID: id, ServiceAccount: "hub", AccountUID: id, Port: 8443}, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{{3}}}
			o := value.OwnerConfigurationObservation{Configuration: c, ObservedAt: now, FreshUntil: now.Add(4 * time.Second)}
			until := o.FreshUntil
			if mode == "caller-deadline" {
				until = now.Add(400 * time.Millisecond)
			}
			ctx, cancel := context.WithDeadline(t.Context(), until)
			defer cancel()
			stored, fenced := false, false
			s := OwnerConfigurationObserver{Now: func() time.Time { return now }, Reader: ownerConfigFunc(func(context.Context) (value.OwnerConfigurationObservation, error) {
				switch mode {
				case "missing":
					return value.OwnerConfigurationObservation{}, value.ErrUnavailable
				case "expired":
					o.FreshUntil = now
				case "cancelled":
					cancel()
				}
				return o, nil
			}), Ledger: ownerLedgerFake{observe: func(ctx context.Context, _ value.OwnerConfigurationObservation) error {
				stored = true
				end, ok := ctx.Deadline()
				if !ok || !end.Equal(until) {
					t.Fatal("incorrect observation deadline", end, until)
				}
				if mode == "conflict" {
					return value.ErrConflict
				}
				return nil
			}, fence: func(ctx context.Context, at time.Time) error {
				fenced = true
				if at != now || ctx.Err() != nil {
					t.Fatal("lost source fence")
				}
				return nil
			}}}
			err := s.Observe(ctx)
			valid := mode == "normal" || mode == "caller-deadline" || mode == "source-deadline"
			if (err == nil) != valid || fenced == valid || stored != (valid || mode == "conflict") {
				t.Fatal(err, stored, fenced)
			}
			if mode == "conflict" && !errors.Is(err, value.ErrConflict) {
				t.Fatal(err)
			}
		})
	}
}
