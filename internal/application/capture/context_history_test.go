package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/targets"
)

// Test-only history reader: the SQL visibility rules are qualified by the
// custody integration suite, not here.
type historyReaderFixture struct {
	f        *investigationFixture
	listed   value.HistoryQuery
	settings value.CaptureSettings
	err      error
}

func (h *historyReaderFixture) ListCaptureHistory(_ context.Context, q value.HistoryQuery) (value.HistoryPage, error) {
	h.listed = q
	return value.HistoryPage{ObservedAt: h.f.now, ValidUntil: h.f.now.Add(5 * time.Second)}, h.err
}
func (h *historyReaderFixture) ReadCaptureSettings(_ context.Context, q value.SettingsQuery) (value.CaptureSettings, error) {
	s := h.settings
	s.CaptureID = q.CaptureID
	return s, h.err
}

// Test-only regional workload LIST: the workload object with zero Pods.
type workloadObserverFixture struct {
	f        *investigationFixture
	uid      string
	err      error
	observed int
}

func (w *workloadObserverFixture) ObserveWorkloadRestarts(_ context.Context, r targets.RestartRequest) (targets.RestartObservation, error) {
	w.observed++
	return targets.RestartObservation{ClusterID: r.ClusterID, Namespace: configuration.NamespaceRef{Name: r.Namespace, UID: "ns"}, Workload: configuration.WorkloadRef{Kind: r.Kind, Name: r.Name, UID: w.uid}, Pods: []targets.PodRestarts{}, ObservedAt: w.f.now, FreshUntil: w.f.now.Add(5 * time.Second)}, w.err
}

func historyService(f *investigationFixture) (ContextHistoryService, *historyReaderFixture) {
	s, r, _ := historyServiceWithWorkloads(f)
	return s, r
}

func historyServiceWithWorkloads(f *investigationFixture) (ContextHistoryService, *historyReaderFixture, *workloadObserverFixture) {
	r := &historyReaderFixture{f: f, settings: value.CaptureSettings{ClusterID: fixtureID(4), NamespaceUID: "ns", WorkloadUID: "deployment", Namespace: "payments", WorkloadKind: "Deployment", WorkloadName: "api", RequestedSeconds: 120, ExpiresAt: f.now.Add(time.Hour), ObservedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}}
	w := &workloadObserverFixture{f: f, uid: "deployment"}
	return ContextHistoryService{RootID: f.svc.RootID, InstallationID: f.svc.InstallationID, Reader: r, Targets: f, Workloads: w, Previews: f.svc, Recovery: f, Now: func() time.Time { return f.now }}, r, w
}

func TestContextHistoryListsAWorkloadWithoutPods(t *testing.T) {
	f := newInvestigationFixture()
	s, r, w := historyServiceWithWorkloads(f)
	ref := f.intent().Target
	// Scaled to zero: no Pod resolves, yet history lists by the workload's
	// current object identity (memory rule: stored reads need no live Pods).
	f.missing = true
	if _, err := s.List(t.Context(), f.source(t, t.Context()), ref, []value.HistoryOrigin{value.HistoryManual}, nil, 20); err != nil {
		t.Fatal("history of a workload without Pods", err)
	}
	if want := authorization.WorkloadScope(fixtureID(4), "ns", "deployment"); r.listed.Target != want || r.listed.Limit != 20 || r.listed.Identity.Principal != f.actor || f.targetReads.Load() != 0 || w.observed != 1 {
		t.Fatal("history not keyed by the current workload identity", r.listed, f.targetReads.Load())
	}
	// Recreated under the same name: the new UID is what the reader gets.
	w.uid = "deployment-recreated"
	if _, err := s.List(t.Context(), f.source(t, t.Context()), ref, []value.HistoryOrigin{value.HistoryManual}, nil, 20); err != nil || r.listed.Target.WorkloadUID != "deployment-recreated" {
		t.Fatal("recreated workload", err, r.listed.Target)
	}
	// An absent workload object is refused.
	w.err = targets.ErrUnavailable
	if _, err := s.List(t.Context(), f.source(t, t.Context()), ref, []value.HistoryOrigin{value.HistoryManual}, nil, 20); err == nil {
		t.Fatal("history listed for a workload that does not resolve")
	}
	// An explicit Pod target is itself the workload.
	f.missing = false
	pod := targets.WorkloadRequest{ClusterID: fixtureID(4), Namespace: "payments", Kind: "Pod", Name: "api-a"}
	f.target.Request.Workload = configuration.WorkloadRef{Kind: "Pod", Name: "api-a", UID: "pod"}
	f.target.Pin.ControllerUID = ""
	if _, err := s.List(t.Context(), f.source(t, t.Context()), pod, []value.HistoryOrigin{value.HistoryManual}, nil, 20); err != nil || r.listed.Target != f.target.Target() {
		t.Fatal("pod history", err, r.listed.Target)
	}
}

func TestContextRepeatRunsTheNormalPreviewForTheOriginalWorkload(t *testing.T) {
	f := newInvestigationFixture()
	s, r := historyService(f)
	result, settings, err := s.PreviewRepeat(t.Context(), f.source(t, t.Context()), fixtureID(41), nil)
	if err != nil || settings.CaptureID != fixtureID(41) || result.Preview.Intent.RequestedSeconds != 120 || result.Preview.Intent.Target.Name != "api" || result.Assessment.Retention.AccessAgeSeconds != 120 {
		t.Fatal("repeat did not restore the original target and retention", err, result.Preview.Intent)
	}
	// Recreated workload: the same name now resolves to another UID.
	r.settings.WorkloadUID = "deployment-before-recreation"
	if _, _, err := s.PreviewRepeat(t.Context(), f.source(t, t.Context()), fixtureID(41), nil); !errors.Is(err, value.ErrTargetReplaced) {
		t.Fatal("recreated workload repeated silently", err)
	}
	// Current eligibility is checked before the replacement is reported.
	f.identityChange = "scopes" // evidence:read only: no collection eligibility
	if _, _, err := s.PreviewRepeat(t.Context(), f.source(t, t.Context()), fixtureID(41), nil); err == nil || errors.Is(err, value.ErrTargetReplaced) {
		t.Fatal("replacement disclosed without current eligibility", err)
	}
	// Without history visibility there is no repeat.
	f.identityChange = ""
	r.settings.WorkloadUID = "deployment"
	r.err = value.ErrDenied
	if _, _, err := s.PreviewRepeat(t.Context(), f.source(t, t.Context()), fixtureID(41), nil); !errors.Is(err, value.ErrDenied) {
		t.Fatal("repeat without history visibility", err)
	}
}

func TestContextPreviewRepeatRejectsInvalidOriginal(t *testing.T) {
	f := newInvestigationFixture()
	if _, err := f.svc.PreviewRepeat(t.Context(), f.source(t, t.Context()), f.intent(), authorization.Target{ClusterID: "x"}); !errors.Is(err, value.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := f.svc.PreviewRepeat(t.Context(), f.source(t, t.Context()), f.intent(), authorization.Target{ClusterID: fixtureID(4), NamespaceUID: "ns", WorkloadUID: "deployment"}); err != nil {
		t.Fatal(err)
	}
}
