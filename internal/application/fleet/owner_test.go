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

type ownerConfigFunc func(context.Context) (value.OwnerConfigurationObservation, error)

func (f ownerConfigFunc) ReadOwnerConfiguration(ctx context.Context) (value.OwnerConfigurationObservation, error) {
	return f(ctx)
}

type ownerEndpointFunc func(context.Context, value.OwnerBinding) (value.OwnerEndpoint, error)

func (f ownerEndpointFunc) OwnerEndpoint(ctx context.Context, b value.OwnerBinding) (value.OwnerEndpoint, error) {
	return f(ctx, b)
}

func TestOwnerRouteKeepsOriginalConfigurationAndDeadline(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	for _, mode := range []string{"valid", "foreign-scope", "unavailable", "suspended", "changed-config", "changed-roots", "changed-protection", "suspend-during-discovery", "wrong-endpoint", "changed-pool", "expired", "cancelled", "cached-first-observation"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			start := now
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "hub", ServiceUID: id, Deployment: "hub", DeploymentUID: id, ServiceAccount: "hub", AccountUID: id, Port: 9443}
			b := value.OwnerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}
			// Tiny opaque roots isolate orchestration; the X.509 adapter and real
			// API fixture independently qualify actual DER and protection.
			c := value.OwnerConfiguration{Pool: p, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}, ProtectionDigest: artifact.Digest{1}, IssuerRoots: [][]byte{{1}}}
			reads, calls := 0, 0
			s := OwnerRoutes{Now: func() time.Time { return now }}
			s.Configurations = ownerConfigFunc(func(context.Context) (value.OwnerConfigurationObservation, error) {
				reads++
				o := value.OwnerConfigurationObservation{Configuration: c.Clone(), ObservedAt: now, FreshUntil: now.Add(4 * time.Second)}
				if reads == 1 {
					switch mode {
					case "unavailable":
						return o, errors.New("unavailable")
					case "suspended":
						o.Configuration.Suspended = true
					case "cached-first-observation":
						o.ObservedAt = start.Add(-time.Second)
						o.FreshUntil = start.Add(3 * time.Second)
					}
				} else {
					switch mode {
					case "changed-config":
						o.Configuration.Revision.Generation++
					case "changed-roots":
						o.Configuration.IssuerRoots[0][0] = 2
					case "changed-protection":
						o.Configuration.ProtectionDigest[0] = 2
					case "suspend-during-discovery":
						o.Configuration.Suspended = true
					}
				}
				return o, nil
			})
			s.Endpoints = ownerEndpointFunc(func(context.Context, value.OwnerBinding) (value.OwnerEndpoint, error) {
				calls++
				now = now.Add(time.Second)
				e := value.OwnerEndpoint{Binding: b, Pool: p, Pod: "owner-pod", ReplicaSetUID: id, Addresses: []string{"10.2.3.4"}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
				switch mode {
				case "wrong-endpoint":
					e.Binding.ProcessEpoch = "22222222-2222-4222-8222-222222222222"
				case "changed-pool":
					e.Pool.Port++
				case "expired":
					now = start.Add(4 * time.Second)
				case "cancelled":
					cancel()
				}
				return e, nil
			})
			if mode == "foreign-scope" {
				b.IssuerEpoch = "22222222-2222-4222-8222-222222222222"
			}
			got, err := s.CurrentOwnerRoute(ctx, b)
			if mode != "valid" && mode != "cached-first-observation" {
				if err == nil || got.Configuration.Configuration.Valid() {
					t.Fatal("unsafe route escaped")
				}
				if (mode == "foreign-scope" || mode == "suspended" || mode == "unavailable") && calls != 0 {
					t.Fatal("discovered before configuration check")
				}
				return
			}
			wantUntil := start.Add(4 * time.Second)
			if mode == "cached-first-observation" {
				wantUntil = start.Add(3 * time.Second)
			}
			if err != nil || !got.Valid(now) || reads != 2 || calls != 1 || !got.FreshUntil.Equal(wantUntil) {
				t.Fatal("original routing deadline lost", err)
			}
			c.IssuerRoots[0][0] = 3
			if got.Configuration.Configuration.IssuerRoots[0][0] != 1 {
				t.Fatal("caller-owned trust mutated retained route")
			}
		})
	}
}
