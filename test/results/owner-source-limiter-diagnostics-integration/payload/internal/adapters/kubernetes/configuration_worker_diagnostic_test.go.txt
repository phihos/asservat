package kubernetes

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	authz "k8s.io/api/authorization/v1"
)

func TestConfigurationWorkerDiagnosticMutationKeepsActualGraph(t *testing.T) {
	for _, mode := range []string{"positive", "source", "deployment"} {
		t.Run(mode, func(t *testing.T) {
			f := newConfigurationSourcePathFixture(t)
			var boundaries atomic.Int32
			f.extraHandler = func(w http.ResponseWriter, r *http.Request) bool {
				switch mode {
				case "source":
					if strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicybindings/cfg-owner") && boundaries.Add(1) == 2 {
						f.fault.Store(4) // Change source after its first actual probe GET.
					}
				case "deployment":
					if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/deployments/"+f.source.input.Deployment.Name) && boundaries.Add(1) == 2 {
						f.workloadVersion.Store(2)
					}
				}
				return false
			}
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			_, err := f.source.readConfigurationWorkerNative(ctx)
			wantCount := int32(33)
			switch mode {
			case "positive":
				if err != nil {
					t.Fatal(err)
				}
			case "source":
				wantCount = 30
				requireConfigurationSourceCode(t, err, configurationSourceSourcesChanged, cfg.ErrChanged)
			case "deployment":
				wantCount = 31
				requireConfigurationSourceCode(t, err, configurationSourceDeploymentFinalBound, cfg.ErrChanged)
			}
			if f.requests.Load() != wantCount || f.probes.Load() != 3 || f.secretWrites.Load() != 0 {
				t.Fatal("diagnostic changed original graph or added an effect", f.requests.Load(), f.probes.Load(), f.secretWrites.Load())
			}
		})
	}
}

func TestConfigurationWorkerDiagnosticFinalPredicatesKeepClockOrder(t *testing.T) {
	// Advance only the existing injectable source clock at the last namespace
	// response. Every real request, parser, limiter and denial remains in place.
	checks := []configurationSourceCheck{configurationSourceUnknown, configurationSourceFinalDeadline, configurationSourceInitialFleetValid, configurationSourceFinalFleetValid, configurationSourceObservationMatch}
	for failAt, want := range checks {
		t.Run(want.String(), func(t *testing.T) {
			f := newConfigurationSourcePathFixture(t)
			base := time.Now()
			var final atomic.Bool
			var namespaces, samples atomic.Int32
			f.source.client.now = func() time.Time {
				if final.Load() {
					if n := samples.Add(1); failAt != 0 && n == int32(failAt) {
						return base.Add(6 * time.Second)
					}
				}
				return base
			}
			f.extraHandler = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == "/api/v1/namespaces/"+f.source.input.Namespace.Name && namespaces.Add(1) == 2 {
					final.Store(true)
				}
				return false
			}
			ctx, stop := context.WithDeadline(context.Background(), base.Add(5*time.Second))
			defer stop()
			_, err := f.source.readConfigurationWorkerNative(ctx)
			wantSamples := int32(failAt)
			if failAt == 0 {
				wantSamples = 4
				if err != nil {
					t.Fatal(err)
				}
			} else {
				requireConfigurationSourceCode(t, err, want, cfg.ErrUnavailable)
			}
			if ctx.Err() != nil || samples.Load() != wantSamples || f.requests.Load() != 33 || f.probes.Load() != 3 {
				t.Fatal("predicate was resampled, reordered or graph changed", samples.Load(), wantSamples, f.requests.Load(), f.probes.Load(), ctx.Err())
			}
		})
	}
}

func TestConfigurationWorkerDiagnosticProbeDetailsAndJoinedPriority(t *testing.T) {
	t.Run("exact-helper", func(t *testing.T) {
		f := newConfigurationSourcePathFixture(t)
		f.fault.Store(1)
		_, _, err := f.source.fleet.protection.proveObjectIdentity(context.Background())
		requireConfigurationSourceCode(t, err, configurationSourceProbeAccessVerdict, cfg.ErrUnavailable)
		if f.requests.Load() != 2 || f.probes.Load() != 0 {
			t.Fatal("unexpected probe retry or denied PUT", f.requests.Load(), f.probes.Load())
		}
	})
	t.Run("joined-index-priority", func(t *testing.T) {
		f := newConfigurationSourcePathFixture(t)
		all := make(chan struct{})
		var arrived atomic.Int32
		f.extraHandler = func(w http.ResponseWriter, r *http.Request) bool {
			if !strings.HasSuffix(r.URL.Path, "/selfsubjectaccessreviews") {
				return false
			}
			if arrived.Add(1) == 3 {
				close(all)
			}
			select {
			case <-all:
			case <-r.Context().Done():
				return true
			}
			permissionReply(w, authz.SelfSubjectAccessReview{Status: authz.SubjectAccessReviewStatus{Allowed: false}})
			return true
		}
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, err := f.source.readConfigurationWorkerNative(ctx)
		requireConfigurationSourceCode(t, err, configurationSourceProbeWorkload, cfg.ErrUnavailable)
		if arrived.Load() != 3 || f.requests.Load() != 13 || f.probes.Load() != 0 {
			t.Fatal("all started probes did not join at the original failure boundary", arrived.Load(), f.requests.Load(), f.probes.Load())
		}
	})
}

func TestConfigurationWorkerDiagnosticBlockedReadKeepsOriginalDeadline(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	var reads atomic.Int32
	f.extraHandler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/deployments/"+f.source.input.Deployment.Name) && reads.Add(1) == 2 {
			<-r.Context().Done()
			return true
		}
		return false
	}
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	_, err := f.source.readConfigurationWorkerNative(ctx)
	requireConfigurationSourceCode(t, err, configurationSourceDeploymentFinalRead, context.DeadlineExceeded)
	if ctx.Err() != context.DeadlineExceeded || reads.Load() != 2 || f.requests.Load() != 31 || f.probes.Load() != 3 {
		t.Fatal("blocked native read retried or escaped original end", ctx.Err(), reads.Load(), f.requests.Load(), f.probes.Load())
	}
}

func TestConfigurationWorkerDiagnosticGuardSubcode(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	f.extraHandler = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicies/cfg-owner") {
			permissionReply(w, map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy", "metadata": map[string]any{"name": "synthetic-private-wrong-object"}})
			return true
		}
		return false
	}
	_, err := f.source.readConfigurationWorkerNative(context.Background())
	requireConfigurationSourceCode(t, err, configurationSourceGuardsFirst, cfg.ErrChanged)
	if !strings.Contains(err.Error(), "source.guard-owner: source.guard-policy-identity") || strings.Contains(err.Error(), "synthetic-private") || f.requests.Load() != 6 || f.probes.Load() != 0 {
		t.Fatal("guard deciding predicate hidden or diagnostic leaked values", err, f.requests.Load())
	}
}

func TestConfigurationWorkerDiagnosticCodesSurviveNormalizedProjection(t *testing.T) {
	private := errors.New("synthetic-private-source-and-token")
	source := configurationSourceError(configurationSourceValuesFinal, configurationSourceError(configurationSourceValuesOwnerRead, private))
	native := ownerOperationError(ownerNativeSource, source).(*ownerOperationDiagnostic)
	if !errors.Is(native, private) || strings.Contains(native.Error(), private.Error()) {
		t.Fatal("native diagnostic changed cause or leaked it")
	}
	projection := &ownerProjectionDiagnostic{check: projectionCheckFinalNative, cause: cfg.ErrUnavailable, native: projectionNativeCodes(native)}
	if !errors.Is(projection, cfg.ErrUnavailable) || errors.Is(projection, private) || !strings.Contains(projection.Error(), "native.source-branch: source.values-final: source.values-owner-read") {
		t.Fatal("normalization lost source codes or reattached cause", projection)
	}
	copy := projectionFixedCodes(projection)
	if copy.cause != nil || copy.native.cause != nil || copy.native.source == native.source || copy.native.source.detail == native.source.detail {
		t.Fatal("retained error or aliased source diagnostic")
	}
	for d := copy.native.source; d != nil; d = d.detail {
		if d.cause != nil {
			t.Fatal("fixed source clone retained original cause")
		}
	}
	unknown := configurationSourceError(configurationSourceCheck(255), configurationSourceHostileError{})
	if unknown.Error() != "source.unknown" {
		t.Fatal("unknown diagnostic was not closed")
	}
	var typedNil *configurationWorkerDiagnostic
	if configurationSourceCodes(typedNil) != nil {
		t.Fatal("typed nil produced a diagnostic")
	}
}

type configurationSourceHostileError struct{}

func (configurationSourceHostileError) Error() string { panic("raw error text must never be rendered") }

func requireConfigurationSourceCode(t *testing.T, err error, want configurationSourceCheck, classification error) {
	t.Helper()
	var actual *configurationWorkerDiagnostic
	if err == nil || !errors.Is(err, classification) || !errors.As(err, &actual) || actual == nil || actual.check != want {
		t.Fatal("incorrect fixed source diagnostic", err, want, classification)
	}
}
