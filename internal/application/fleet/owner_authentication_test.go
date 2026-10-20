package fleet

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type ownerRegistryFunction func(context.Context, value.OwnerCertificate) (value.OwnerRegistrationObservation, error)

func (f ownerRegistryFunction) ReadOwnerRegistration(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	return f(ctx, c)
}

type ownerRouteFunction func(context.Context, value.OwnerBinding) (value.OwnerRoute, error)

func (f ownerRouteFunction) CurrentOwnerRoute(ctx context.Context, b value.OwnerBinding) (value.OwnerRoute, error) {
	return f(ctx, b)
}

type ownerProtectionFunction func(context.Context, value.OwnerPool) (value.OwnerProtection, error)

func (f ownerProtectionFunction) ReadOwnerProtection(ctx context.Context, p value.OwnerPool) (value.OwnerProtection, error) {
	return f(ctx, p)
}

type ownerConnectionFixture struct {
	certificate value.OwnerCertificate
	revalidate  func(value.OwnerConfigurationObservation) (value.OwnerCertificate, error)
}

func (c ownerConnectionFixture) OwnerCertificate() (value.OwnerCertificate, error) {
	return c.certificate, nil
}
func (c ownerConnectionFixture) VerifyCurrentOwner(o value.OwnerConfigurationObservation) (value.OwnerCertificate, error) {
	return c.revalidate(o)
}

func TestOwnerAuthenticationRequiresAllCurrentBoundaries(t *testing.T) {
	testOwnerCurrentBoundaries(t, "peer")
}
func TestOwnerServingRequiresAllCurrentBoundaries(t *testing.T) {
	testOwnerCurrentBoundaries(t, "server")
}

func testOwnerCurrentBoundaries(t *testing.T, kind string) {
	const id = "11111111-1111-4111-8111-111111111111"
	const other = "22222222-2222-4222-8222-222222222222"
	for _, mode := range []string{"valid", "expired-first-registry", "cached-first-registry", "retired-during-route", "changed-config", "changed-enrollment", "wrong-registry-certificate", "wrong-route-process", "wrong-route-pool", "wrong-pod-name", "wrong-replica", "protection-missing", "protection-changed", "protection-wrong-pool", "protection-invalid", "protection-after-invalid", "protection-after-wrong-pool", "protection-native-step", "protection-private-step", "protection-deadline", "protection-canceled", "protection-unreported", "removed-root", "connection-changed", "cancelled", "expired-during-crypto"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			start := now
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var reports []string
			if mode != "protection-unreported" {
				ctx = WithRefusalSteps(ctx, func(step string) { reports = append(reports, step) })
			}
			pool := value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "hub", ServiceUID: id, Deployment: "hub", DeploymentUID: id, ServiceAccount: "hub", AccountUID: id, Port: 8443}
			binding := value.OwnerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}
			cert := value.OwnerCertificate{Binding: binding, Usage: "client", Digest: artifact.Digest{1}, NotBefore: start.Add(-time.Minute), NotAfter: start.Add(10 * time.Minute)}
			if kind == "server" {
				cert.Usage = "server"
			}
			claimed := start.Add(-time.Second)
			_, hold, _ := value.OwnerCertificateWindow(claimed)
			enrollment := value.OwnerEnrollment{ID: id, Binding: binding, Usage: cert.Usage, Pool: pool, SourceUID: id, Pod: "hub-pod", ReplicaSet: "hub-rs", ReplicaSetUID: id, PublicKeyDigest: artifact.Digest{2}, InitialTokenDigest: artifact.Digest{3}, InitialWorkloadDigest: artifact.Digest{4}, InitialProtectionDigest: artifact.Digest{5}, ClaimedAt: claimed, InitialHoldUntil: hold.Add(time.Minute)}
			config := value.OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{6}}, ProtectionDigest: artifact.Digest{7}, IssuerRoots: [][]byte{{8}}}
			observation := func() value.OwnerConfigurationObservation {
				return value.OwnerConfigurationObservation{Configuration: config.Clone(), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
			}
			reads, guards, crypto := 0, 0, 0
			s := OwnerAuthenticator{Now: func() time.Time { return now }}
			s.Registry = ownerRegistryFunction(func(_ context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
				reads++
				out := value.OwnerRegistrationObservation{Enrollment: enrollment, Certificate: cert, Configuration: observation(), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
				if reads == 1 {
					switch mode {
					case "expired-first-registry":
						out.FreshUntil = now
					case "cached-first-registry":
						out.ObservedAt = start.Add(-time.Second)
						out.FreshUntil = start.Add(4 * time.Second)
					case "wrong-registry-certificate":
						out.Certificate.Digest[0]++
					}
				}
				if reads > 1 {
					switch mode {
					case "retired-during-route":
						return out, errors.New("retired")
					case "changed-config":
						out.Configuration.Configuration.Revision.Generation++
					case "changed-enrollment":
						out.Enrollment.ID = other
					}
				}
				return out, nil
			})
			s.Protection = ownerProtectionFunction(func(_ context.Context, p value.OwnerPool) (value.OwnerProtection, error) {
				guards++
				out := value.OwnerProtection{Pool: pool, Digest: artifact.Digest{9}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
				switch mode {
				case "protection-missing":
					return out, errors.New("missing")
				case "protection-wrong-pool":
					out.Pool.NamespaceUID = other
				case "protection-invalid":
					out.FreshUntil = now
				case "protection-after-invalid":
					if guards > 1 {
						out.FreshUntil = now
					}
				case "protection-after-wrong-pool":
					if guards > 1 {
						out.Pool.NamespaceUID = other
					}
				case "protection-native-step":
					return out, ownerProtectionDiagnosticError{"source.guard-policy-read", false}
				case "protection-private-step":
					return out, ownerProtectionDiagnosticError{"source.guard-policy-read: private-token-host", false}
				case "protection-unreported":
					return out, ownerProtectionDiagnosticError{"", true}
				case "protection-deadline":
					return out, context.DeadlineExceeded
				case "protection-canceled":
					return out, context.Canceled
				case "protection-changed":
					if guards > 1 {
						out.Digest[0]++
					}
				}
				return out, nil
			})
			s.Routes = ownerRouteFunction(func(_ context.Context, b value.OwnerBinding) (value.OwnerRoute, error) {
				now = now.Add(time.Second)
				endpoint := value.OwnerEndpoint{Binding: binding, Pool: pool, Pod: enrollment.Pod, ReplicaSetUID: enrollment.ReplicaSetUID, Addresses: []string{"10.0.1.2"}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
				switch mode {
				case "wrong-route-process":
					endpoint.Binding.ProcessEpoch = other
				case "wrong-route-pool":
					endpoint.Pool.Port++
				case "wrong-pod-name":
					endpoint.Pod = "another-pod"
				case "wrong-replica":
					endpoint.ReplicaSetUID = other
				case "cancelled":
					cancel()
				}
				return value.OwnerRoute{Configuration: observation(), Endpoint: endpoint, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
			})
			connection := ownerConnectionFixture{certificate: cert, revalidate: func(c value.OwnerConfigurationObservation) (value.OwnerCertificate, error) {
				crypto++
				out := cert
				if crypto > 1 {
					switch mode {
					case "removed-root":
						return out, errors.New("untrusted")
					case "connection-changed":
						out.Binding.ProcessEpoch = other
					case "expired-during-crypto":
						now = start.Add(5 * time.Second)
					}
				}
				return out, nil
			}}
			var got value.AuthenticatedOwner
			var deadline time.Time
			var err error
			if kind == "server" {
				deadline, err = s.CheckOwnerServing(ctx, servingIdentityFixture{connection})
			} else if kind == "client" {
				deadline, err = s.CheckOwnerClient(ctx, clientIdentityFixture{connection})
			} else if kind == "client-observation" {
				got, err = s.ObserveOwnerClient(ctx, clientIdentityFixture{connection})
				deadline = got.ValidUntil
			} else {
				got, err = s.AuthenticateOwner(ctx, connection)
				deadline = got.ValidUntil
			}
			wantReport := map[string]string{
				"protection-missing":          "protection-before/read/other",
				"protection-wrong-pool":       "protection-before/pool",
				"protection-invalid":          "protection-before/invalid",
				"protection-after-invalid":    "protection-after/invalid",
				"protection-after-wrong-pool": "protection-after/pool",
				"protection-changed":          "protection-after/digest",
				"protection-native-step":      "protection-before/read/source.guard-policy-read",
				"protection-private-step":     "protection-before/read/other",
				"protection-deadline":         "protection-before/read/deadline",
				"protection-canceled":         "protection-before/read/canceled",
			}[mode]
			if wantReport != "" && (len(reports) != 1 || !strings.HasPrefix(reports[0], wantReport+"@") || !errors.Is(err, value.ErrUnavailable)) {
				t.Fatalf("protection refusal lost its closed reason or error class: %v, %v", reports, err)
			}
			if mode != "valid" && mode != "cached-first-registry" {
				if err == nil || got != (value.AuthenticatedOwner{}) || !deadline.IsZero() {
					t.Fatal("invalid peer accepted", got)
				}
				return
			}
			until := start.Add(5 * time.Second)
			if mode == "cached-first-registry" {
				until = start.Add(4 * time.Second)
			}
			if err != nil || ((kind == "peer" || kind == "client-observation") && (!got.Valid(now) || got.Certificate != cert || got.EnrollmentID != enrollment.ID)) || !deadline.Equal(until) || reads != 2 || guards != 2 || crypto != 2 {
				t.Fatal("lost current boundary or original deadline", err, got, reads, guards, crypto)
			}
		})
	}
}

type ownerProtectionDiagnosticError struct {
	step      string
	forbidden bool
}

func (ownerProtectionDiagnosticError) Error() string { panic("private error text inspected") }
func (e ownerProtectionDiagnosticError) FixedStep() string {
	if e.forbidden {
		panic("unreported dependency inspected")
	}
	return e.step
}

type servingIdentityFixture struct{ ownerConnectionFixture }

func (s servingIdentityFixture) ServingCertificate() (value.OwnerCertificate, error) {
	return s.OwnerCertificate()
}
func (s servingIdentityFixture) VerifyServingCertificate(o value.OwnerConfigurationObservation) (value.OwnerCertificate, error) {
	return s.VerifyCurrentOwner(o)
}

func TestOwnerClientRequiresAllCurrentBoundaries(t *testing.T) {
	testOwnerCurrentBoundaries(t, "client")
}

type clientIdentityFixture struct{ ownerConnectionFixture }

func (s clientIdentityFixture) ClientCertificate() (value.OwnerCertificate, error) {
	return s.OwnerCertificate()
}
func (s clientIdentityFixture) VerifyClientCertificate(o value.OwnerConfigurationObservation) (value.OwnerCertificate, error) {
	return s.VerifyCurrentOwner(o)
}

func TestOwnerClientObservationRequiresAllCurrentBoundaries(t *testing.T) {
	testOwnerCurrentBoundaries(t, "client-observation")
}
