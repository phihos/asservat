package fleet

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type ownerRouteDiagnosticError struct{ unreported bool }

func (ownerRouteDiagnosticError) Error() string     { panic("provider text inspected") }
func (ownerRouteDiagnosticError) FixedStep() string { panic("provider diagnostic inspected") }
func (e ownerRouteDiagnosticError) Is(error) bool {
	if e.unreported {
		panic("unreported provider error inspected")
	}
	return false
}

type ownerRouteDiagnosticFixture struct {
	route   OwnerRoutes
	binding value.OwnerBinding
	config  value.OwnerConfiguration
	start   time.Time
	calls   []string
}

func newOwnerRouteDiagnosticFixture(t *testing.T, mode string, cancel context.CancelFunc, parentUntil time.Time) *ownerRouteDiagnosticFixture {
	t.Helper()
	const id = "11111111-1111-4111-8111-111111111111"
	const other = "22222222-2222-4222-8222-222222222222"
	f := &ownerRouteDiagnosticFixture{start: time.Now().UTC()}
	now := f.start
	pool := value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "hub", ServiceUID: id, Deployment: "hub", DeploymentUID: id, ServiceAccount: "hub", AccountUID: id, Port: 9443}
	f.binding = value.OwnerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}
	f.config = value.OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{{3}}}
	checkContext := func(ctx context.Context) {
		t.Helper()
		until, ok := ctx.Deadline()
		if !ok || until.After(parentUntil) || until.After(f.start.Add(5*time.Second)) {
			t.Fatal("route read widened the original operation interval")
		}
	}
	f.route.Now = func() time.Time { return now }
	reads := 0
	f.route.Configurations = ownerConfigFunc(func(ctx context.Context) (value.OwnerConfigurationObservation, error) {
		checkContext(ctx)
		reads++
		stage := "config-first"
		if reads == 2 {
			stage = "config-final"
		}
		f.calls = append(f.calls, stage)
		o := value.OwnerConfigurationObservation{Configuration: f.config.Clone(), ObservedAt: now, FreshUntil: now.Add(4 * time.Second)}
		switch mode {
		case stage + "-error":
			return o, ownerRouteDiagnosticError{}
		case stage + "-deadline":
			return o, context.DeadlineExceeded
		case stage + "-canceled":
			return o, context.Canceled
		case stage + "-invalid":
			o.FreshUntil = now
		}
		if reads == 1 {
			switch mode {
			case "unreported":
				return o, ownerRouteDiagnosticError{unreported: true}
			case "config-first-suspended":
				o.Configuration.Suspended = true
			case "current-route":
				o.FreshUntil = now.Add(time.Second)
			}
		} else {
			switch mode {
			case "config-final-changed":
				o.Configuration.Revision.Generation++
			case "context-canceled":
				cancel()
			}
		}
		return o, nil
	})
	f.route.Endpoints = ownerEndpointFunc(func(ctx context.Context, b value.OwnerBinding) (value.OwnerEndpoint, error) {
		checkContext(ctx)
		f.calls = append(f.calls, "endpoints")
		if mode == "current-route" {
			now = f.start.Add(2 * time.Second)
		}
		e := value.OwnerEndpoint{Binding: b, Pool: pool, Pod: "owner-pod", ReplicaSetUID: id, Addresses: []string{"10.2.3.4"}, ObservedAt: now, FreshUntil: now.Add(4 * time.Second)}
		switch mode {
		case "endpoints-error":
			return e, ownerRouteDiagnosticError{}
		case "endpoints-deadline":
			return e, context.DeadlineExceeded
		case "endpoints-canceled":
			return e, context.Canceled
		case "endpoints-binding":
			e.Binding.ProcessEpoch = other
		case "endpoints-pool":
			e.Pool.Port++
		case "endpoints-invalid":
			e.FreshUntil = now
		}
		return e, nil
	})
	if mode == "scope" {
		f.binding.IssuerEpoch = other
	}
	return f
}

func TestOwnerRouteRefusalDiagnosticsKeepBoundaries(t *testing.T) {
	for _, tc := range []struct {
		mode, step string
		calls      []string
	}{
		{"valid", "", []string{"config-first", "endpoints", "config-final"}},
		{"config-first-error", "route-read/config-first/read/other", []string{"config-first"}},
		{"config-first-deadline", "route-read/config-first/read/deadline", []string{"config-first"}},
		{"config-first-canceled", "route-read/config-first/read/canceled", []string{"config-first"}},
		{"config-first-invalid", "route-read/config-first/current", []string{"config-first"}},
		{"config-first-suspended", "route-read/config-first/current", []string{"config-first"}},
		{"scope", "route-read/config-first/scope", []string{"config-first"}},
		{"endpoints-error", "route-read/endpoints/read/other", []string{"config-first", "endpoints"}},
		{"endpoints-deadline", "route-read/endpoints/read/deadline", []string{"config-first", "endpoints"}},
		{"endpoints-canceled", "route-read/endpoints/read/canceled", []string{"config-first", "endpoints"}},
		{"endpoints-binding", "route-read/endpoints/current", []string{"config-first", "endpoints"}},
		{"endpoints-pool", "route-read/endpoints/current", []string{"config-first", "endpoints"}},
		{"endpoints-invalid", "route-read/endpoints/current", []string{"config-first", "endpoints"}},
		{"config-final-error", "route-read/config-final/read/other", []string{"config-first", "endpoints", "config-final"}},
		{"config-final-deadline", "route-read/config-final/read/deadline", []string{"config-first", "endpoints", "config-final"}},
		{"config-final-canceled", "route-read/config-final/read/canceled", []string{"config-first", "endpoints", "config-final"}},
		{"config-final-invalid", "route-read/config-final/current", []string{"config-first", "endpoints", "config-final"}},
		{"config-final-changed", "route-read/config-final/current", []string{"config-first", "endpoints", "config-final"}},
		{"context-canceled", "route-read/context/canceled", []string{"config-first", "endpoints", "config-final"}},
		{"current-route", "route-read/current", []string{"config-first", "endpoints", "config-final"}},
		{"unreported", "", []string{"config-first"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			until, _ := ctx.Deadline()
			var reports []string
			if tc.mode != "unreported" {
				ctx = WithRefusalSteps(ctx, func(step string) { reports = append(reports, step) })
			}
			f := newOwnerRouteDiagnosticFixture(t, tc.mode, cancel, until)
			out, err := f.route.CurrentOwnerRoute(ctx, f.binding)
			if !slices.Equal(f.calls, tc.calls) {
				t.Fatal("diagnostics changed read order or short-circuit behavior", f.calls)
			}
			if tc.mode == "valid" {
				if err != nil || !out.Valid(f.start) {
					t.Fatal("valid route changed", err)
				}
			} else {
				want := value.ErrUnavailable
				if tc.mode == "scope" {
					want = value.ErrDenied
				}
				if err != want || out.Endpoint.Binding.Valid() {
					t.Fatal("refusal changed its exact public sentinel or returned a route", err)
				}
			}
			if tc.step == "" {
				if len(reports) != 0 {
					t.Fatal("unexpected diagnostic", reports)
				}
			} else if len(reports) != 1 || !strings.HasPrefix(reports[0], tc.step+"@") {
				t.Fatal("missing closed route refusal stage", reports, tc.step)
			}
		})
	}
}

func TestOwnerRouteRefusalReachesAuthenticatorSink(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	until, _ := ctx.Deadline()
	f := newOwnerRouteDiagnosticFixture(t, "config-first-error", cancel, until)
	b, p, start := f.binding, f.config.Pool, f.start
	cert := value.OwnerCertificate{Binding: b, Usage: "server", Digest: artifact.Digest{1}, NotBefore: start.Add(-time.Minute), NotAfter: start.Add(10 * time.Minute)}
	claimed := start.Add(-time.Second)
	_, hold, _ := value.OwnerCertificateWindow(claimed)
	enrollment := value.OwnerEnrollment{ID: b.PodUID, Binding: b, Usage: cert.Usage, Pool: p, SourceUID: b.PodUID, Pod: "owner-pod", ReplicaSet: "owner-rs", ReplicaSetUID: b.PodUID, PublicKeyDigest: artifact.Digest{2}, InitialTokenDigest: artifact.Digest{3}, InitialWorkloadDigest: artifact.Digest{4}, InitialProtectionDigest: artifact.Digest{5}, ClaimedAt: claimed, InitialHoldUntil: hold.Add(time.Minute)}
	config := value.OwnerConfigurationObservation{Configuration: f.config.Clone(), ObservedAt: start, FreshUntil: start.Add(4 * time.Second)}
	registryReads, protectionReads := 0, 0
	s := OwnerAuthenticator{
		Routes: &f.route, Now: func() time.Time { return start },
		Registry: ownerRegistryFunction(func(context.Context, value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
			registryReads++
			return value.OwnerRegistrationObservation{Enrollment: enrollment, Certificate: cert, Configuration: config, ObservedAt: start, FreshUntil: start.Add(4 * time.Second)}, nil
		}),
		Protection: ownerProtectionFunction(func(context.Context, value.OwnerPool) (value.OwnerProtection, error) {
			protectionReads++
			return value.OwnerProtection{Pool: p, Digest: artifact.Digest{6}, ObservedAt: start, FreshUntil: start.Add(4 * time.Second)}, nil
		}),
	}
	var reports []string
	// ContextStartIngress uses this same sink and fixed prefix at its closing
	// local identity check; route detail must arrive before the summary.
	ctx = WithRefusalSteps(ctx, func(step string) { reports = append(reports, "final-local/"+step) })
	connection := ownerConnectionFixture{certificate: cert, revalidate: func(value.OwnerConfigurationObservation) (value.OwnerCertificate, error) { return cert, nil }}
	_, err := s.CheckOwnerServing(ctx, servingIdentityFixture{connection})
	if !errors.Is(err, value.ErrUnavailable) || registryReads != 1 || protectionReads != 1 || !slices.Equal(f.calls, []string{"config-first"}) {
		t.Fatal("route refusal changed authentication boundaries", err, registryReads, protectionReads, f.calls)
	}
	if len(reports) != 2 || !strings.HasPrefix(reports[0], "final-local/route-read/config-first/read/other@") || !strings.HasPrefix(reports[1], "final-local/route-read@") {
		t.Fatal("receiving diagnostic sink lost detailed route stage", reports)
	}
}
