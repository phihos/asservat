package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	core "k8s.io/api/core/v1"
)

type initialHandoverHistoryFunc func(context.Context) (fleetapp.InitialInstallationObservation, error)

func (f initialHandoverHistoryFunc) ObserveInitialInstallation(ctx context.Context) (fleetapp.InitialInstallationObservation, error) {
	return f(ctx)
}

// These are observation-order tests with synthetic ports. Independent current
// Kubernetes/SQL scope and claim verification remain in their concrete readers.
func TestInitialHandoverObservesSQLAfterOriginalPodTermination(t *testing.T) {
	now := time.Now()
	until := now.Add(5 * time.Second)
	committed := false
	historyCalls, podCalls := 0, 0
	history := initialHandoverHistoryFunc(func(context.Context) (fleetapp.InitialInstallationObservation, error) {
		historyCalls++
		disposition := fleetapp.InitialInstallationAudited
		if committed {
			disposition = fleetapp.InitialInstallationActivated
		}
		return fleetapp.InitialInstallationObservation{Disposition: disposition, ValidUntil: until}, nil
	})
	observePod := func(context.Context) (kube.InitialPreparationPodDisposition, error) {
		podCalls++
		// Activation commits and the original process exits before the terminal
		// Pod observation. A preceding SQL snapshot still said only "audited".
		committed = true
		return kube.InitialPreparationPodDisposition{Phase: core.PodSucceeded, Terminated: true, ExitCode: 0, ValidUntil: until}, nil
	}
	observed, pod, err := observeInitialPreparationResult(context.Background(), history, observePod, func() time.Time { return now })
	if err != nil || !pod.Terminated || observed.Disposition != fleetapp.InitialInstallationActivated || historyCalls != 1 || podCalls != 1 {
		t.Fatalf("successful original Pod paired with stale SQL observation: disposition=%s history=%d pod=%d err=%v", observed.Disposition, historyCalls, podCalls, err)
	}
}

func TestInitialHandoverHistoryCannotOutliveOriginalPodOrRequest(t *testing.T) {
	for _, requestShorter := range []bool{false, true} {
		t.Run(map[bool]string{false: "pod", true: "request"}[requestShorter], func(t *testing.T) {
			now := time.Now()
			podUntil := now.Add(2 * time.Second)
			requestUntil := now.Add(4 * time.Second)
			if requestShorter {
				requestUntil = now.Add(time.Second)
			}
			ctx, cancel := context.WithDeadline(context.Background(), requestUntil)
			defer cancel()
			want := podUntil
			if requestUntil.Before(want) {
				want = requestUntil
			}
			history := initialHandoverHistoryFunc(func(ctx context.Context) (fleetapp.InitialInstallationObservation, error) {
				deadline, ok := ctx.Deadline()
				if !ok || !deadline.Equal(want) {
					t.Fatalf("history deadline %v, want original bound %v", deadline, want)
				}
				return fleetapp.InitialInstallationObservation{Disposition: fleetapp.InitialInstallationActivated, ValidUntil: now.Add(10 * time.Second)}, nil
			})
			pod := func(context.Context) (kube.InitialPreparationPodDisposition, error) {
				return kube.InitialPreparationPodDisposition{ValidUntil: podUntil}, nil
			}
			observed, _, err := observeInitialPreparationResult(ctx, history, pod, func() time.Time { return now })
			if err != nil || !observed.ValidUntil.Equal(want) {
				t.Fatalf("returned history deadline %v, want original bound %v: %v", observed.ValidUntil, want, err)
			}
		})
	}
}

func TestInitialHandoverRejectsExpiredOrCancelledObservation(t *testing.T) {
	for _, stage := range []string{"pod-expired", "pod-cancelled", "history-expired", "history-cancelled", "history-shortened"} {
		t.Run(stage, func(t *testing.T) {
			now := time.Now()
			until := now.Add(2 * time.Second)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			historyCalls := 0
			history := initialHandoverHistoryFunc(func(context.Context) (fleetapp.InitialInstallationObservation, error) {
				historyCalls++
				observedUntil := until
				switch stage {
				case "history-expired":
					now = until
				case "history-cancelled":
					cancel()
				case "history-shortened":
					observedUntil = now
				}
				return fleetapp.InitialInstallationObservation{Disposition: fleetapp.InitialInstallationActivated, ValidUntil: observedUntil}, nil
			})
			pod := func(context.Context) (kube.InitialPreparationPodDisposition, error) {
				switch stage {
				case "pod-expired":
					now = until
				case "pod-cancelled":
					cancel()
				}
				return kube.InitialPreparationPodDisposition{ValidUntil: until}, nil
			}
			if _, _, err := observeInitialPreparationResult(ctx, history, pod, func() time.Time { return now }); !errors.Is(err, mounts.ErrUnavailable) {
				t.Fatalf("expired/cancelled observation returned %v", err)
			}
			if (stage == "pod-expired" || stage == "pod-cancelled") && historyCalls != 0 {
				t.Fatal("history read started after original Pod observation expired/cancelled")
			}
		})
	}
}

func TestInitialHandoverSuccessfulPodNeverSuppliesSQLActivation(t *testing.T) {
	now := time.Now()
	until := now.Add(5 * time.Second)
	pod := func(context.Context) (kube.InitialPreparationPodDisposition, error) {
		return kube.InitialPreparationPodDisposition{Phase: core.PodSucceeded, Terminated: true, ExitCode: 0, ValidUntil: until}, nil
	}
	for _, state := range []fleetapp.InitialInstallationDisposition{fleetapp.InitialInstallationMissing, fleetapp.InitialInstallationPrepared, fleetapp.InitialInstallationAudited} {
		t.Run(string(state), func(t *testing.T) {
			history := initialHandoverHistoryFunc(func(context.Context) (fleetapp.InitialInstallationObservation, error) {
				return fleetapp.InitialInstallationObservation{Disposition: state, ValidUntil: until}, nil
			})
			observed, _, err := observeInitialPreparationResult(context.Background(), history, pod, func() time.Time { return now })
			if err != nil || observed.Disposition != state {
				t.Fatal("Pod result replaced independent SQL disposition", err)
			}
		})
	}
	denied := errors.New("synthetic independent history denial")
	history := initialHandoverHistoryFunc(func(context.Context) (fleetapp.InitialInstallationObservation, error) {
		return fleetapp.InitialInstallationObservation{}, denied
	})
	if _, _, err := observeInitialPreparationResult(context.Background(), history, pod, func() time.Time { return now }); !errors.Is(err, denied) {
		t.Fatal("history denial hidden by successful Pod", err)
	}
}
