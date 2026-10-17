package fleet

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func TestOwnerConfigurationObserverKeepsObservedDeadlineThroughAuditAndAck(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	for _, stage := range []string{"ledger", "audit", "acknowledgement"} {
		for _, callerEarlier := range []bool{false, true} {
			t.Run(stage+map[bool]string{false: "/source-end", true: "/caller-end"}[callerEarlier], func(t *testing.T) {
				now := time.Now().UTC()
				c := value.OwnerConfiguration{Pool: value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "hub", ServiceUID: id, Deployment: "hub", DeploymentUID: id, ServiceAccount: "hub", AccountUID: id, Port: 8443}, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{{3}}}
				o := value.OwnerConfigurationObservation{Configuration: c, ObservedAt: now, FreshUntil: now.Add(80 * time.Millisecond)}
				until := o.FreshUntil
				if callerEarlier {
					until = now.Add(40 * time.Millisecond)
				}
				ctx, cancel := context.WithDeadline(t.Context(), until)
				defer cancel()
				r := audit.Receipt{Key: audit.OwnerConfigurationAuditKey(c), Version: "synthetic-original-version", ETag: "synthetic", Bytes: 1, SHA256: artifact.Digest{4}}
				if !o.Valid(now) || !r.ValidOwnerConfiguration(c) {
					t.Fatal("invalid synthetic original source")
				}
				var calls []string
				check := func(ctx context.Context, at string) {
					calls = append(calls, at)
					got, ok := ctx.Deadline()
					if !ok || !got.Equal(until) {
						t.Fatal("lost original observed/caller end", at, got, until)
					}
					if at == stage {
						<-ctx.Done()
					}
				}
				s := OwnerConfigurationObserver{Now: time.Now,
					Reader: ownerConfigFunc(func(context.Context) (value.OwnerConfigurationObservation, error) { return o, nil }),
					Ledger: ownerLedgerFake{observe: func(ctx context.Context, _ value.OwnerConfigurationObservation) (audit.Receipt, bool, error) {
						check(ctx, "ledger")
						return r, false, nil
					}, fence: func(context.Context, time.Time) error { return nil }},
					Audit: ownerAuditFunc(func(ctx context.Context, _ value.OwnerConfiguration) (audit.Receipt, error) {
						check(ctx, "audit")
						return r, nil
					}),
					Acknowledgements: ownerAckFunc(func(ctx context.Context, _ value.OwnerConfiguration, _ audit.Receipt) error {
						check(ctx, "acknowledgement")
						return nil
					}),
				}
				if err := s.Observe(ctx); err == nil {
					t.Fatal("expired blocking result reported current success")
				}
				want := map[string]int{"ledger": 1, "audit": 2, "acknowledgement": 3}[stage]
				if len(calls) != want {
					t.Fatal("expired original source admitted later work", calls)
				}
			})
		}
	}
}
