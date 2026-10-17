package fleet

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"testing"
	"time"
)

type ownerLedgerFake struct {
	observe func(context.Context, value.OwnerConfigurationObservation) (audit.Receipt, bool, error)
	fence   func(context.Context, time.Time) error
}

func (s ownerLedgerFake) ObserveOwnerConfiguration(ctx context.Context, o value.OwnerConfigurationObservation) (audit.Receipt, bool, error) {
	return s.observe(ctx, o)
}
func (s ownerLedgerFake) FenceOwnerConfiguration(ctx context.Context, at time.Time) error {
	return s.fence(ctx, at)
}

type ownerAuditFunc func(context.Context, value.OwnerConfiguration) (audit.Receipt, error)

func (f ownerAuditFunc) WriteOwnerConfiguration(ctx context.Context, c value.OwnerConfiguration) (audit.Receipt, error) {
	return f(ctx, c)
}

type ownerAckFunc func(context.Context, value.OwnerConfiguration, audit.Receipt) error

func (f ownerAckFunc) AcknowledgeOwnerConfiguration(ctx context.Context, c value.OwnerConfiguration, r audit.Receipt) error {
	return f(ctx, c, r)
}

func TestOwnerConfigurationAcceptanceOrderingAndFailures(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	for _, mode := range []string{"new", "acknowledged", "missing-source", "expired-source", "cancelled-source", "ledger-conflict", "bad-old-receipt", "empty-old-version", "null-old-version", "audit-failed", "bad-new-receipt", "ack-failed"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := value.OwnerConfiguration{Pool: value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "hub", ServiceUID: id, Deployment: "hub", DeploymentUID: id, ServiceAccount: "hub", AccountUID: id, Port: 8443}, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{{3}}}
			o := value.OwnerConfigurationObservation{Configuration: c, ObservedAt: now, FreshUntil: now.Add(time.Second)}
			r := audit.Receipt{Key: audit.OwnerConfigurationAuditKey(c), Version: "synthetic-original-version", ETag: "synthetic", Bytes: 1, SHA256: artifact.Digest{4}}
			observed, written, acked, fenced := 0, 0, 0, 0
			s := OwnerConfigurationObserver{Now: func() time.Time { return now }}
			s.Reader = ownerConfigFunc(func(context.Context) (value.OwnerConfigurationObservation, error) {
				switch mode {
				case "missing-source":
					return value.OwnerConfigurationObservation{}, value.ErrUnavailable
				case "expired-source":
					now = now.Add(time.Second)
				case "cancelled-source":
					cancel()
				}
				return o, nil
			})
			s.Ledger = ownerLedgerFake{observe: func(_ context.Context, got value.OwnerConfigurationObservation) (audit.Receipt, bool, error) {
				observed++
				if got.ObservedAt != o.ObservedAt || got.FreshUntil != o.FreshUntil || !got.Configuration.Equal(c) {
					t.Fatal("original source changed")
				}
				if mode == "ledger-conflict" {
					return audit.Receipt{}, false, value.ErrConflict
				}
				if mode == "bad-old-receipt" {
					return audit.Receipt{}, true, nil
				}
				if mode == "empty-old-version" {
					r.Version = ""
					return r, true, nil
				}
				if mode == "null-old-version" {
					r.Version = "null"
					return r, true, nil
				}
				return r, mode == "acknowledged", nil
			}, fence: func(ctx context.Context, at time.Time) error {
				fenced++
				if ctx.Err() != nil || at != o.ObservedAt {
					t.Fatal("cancelled or retimed negative observation")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded cleanup")
				}
				return nil
			}}
			s.Audit = ownerAuditFunc(func(_ context.Context, got value.OwnerConfiguration) (audit.Receipt, error) {
				written++
				if observed != 1 || !got.Equal(c) {
					t.Fatal("audit preceded acceptance")
				}
				if mode == "audit-failed" {
					return audit.Receipt{}, value.ErrUnavailable
				}
				if mode == "bad-new-receipt" {
					return audit.Receipt{}, nil
				}
				return r, nil
			})
			s.Acknowledgements = ownerAckFunc(func(_ context.Context, got value.OwnerConfiguration, rr audit.Receipt) error {
				acked++
				if written != 1 || !got.Equal(c) || rr != r {
					t.Fatal("ack preceded verified audit")
				}
				if mode == "ack-failed" {
					return value.ErrUnavailable
				}
				return nil
			})
			err := s.Observe(ctx)
			if (mode == "new" || mode == "acknowledged") != (err == nil) {
				t.Fatal("unexpected result", err)
			}
			switch mode {
			case "new", "ack-failed":
				if observed != 1 || written != 1 || acked != 1 || fenced != 0 {
					t.Fatal("wrong acceptance sequence")
				}
			case "acknowledged":
				if observed != 1 || written+acked+fenced != 0 {
					t.Fatal("repeat performed key/audit I/O")
				}
			case "missing-source", "expired-source", "cancelled-source":
				if observed+written+acked != 0 || fenced != 1 {
					t.Fatal("failed source was not fenced")
				}
			case "ledger-conflict", "bad-old-receipt", "empty-old-version", "null-old-version":
				if observed != 1 || written+acked != 0 || fenced != 1 {
					t.Fatal("rejected observation proceeded")
				}
			default:
				if observed != 1 || written != 1 || acked+fenced != 0 {
					t.Fatal("bad audit acknowledged")
				}
			}
			if mode == "ledger-conflict" && !errors.Is(err, value.ErrConflict) {
				t.Fatal("conflict lost")
			}
		})
	}
}
