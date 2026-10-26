package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
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

func historyService(f *investigationFixture) (ContextHistoryService, *historyReaderFixture) {
	r := &historyReaderFixture{f: f, settings: value.CaptureSettings{ClusterID: fixtureID(4), NamespaceUID: "ns", WorkloadUID: "deployment", Namespace: "payments", WorkloadKind: "Deployment", WorkloadName: "api", RequestedSeconds: 120, ObservedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}}
	return ContextHistoryService{RootID: f.svc.RootID, InstallationID: f.svc.InstallationID, Reader: r, Targets: f, Previews: f.svc, Recovery: f, Now: func() time.Time { return f.now }}, r
}

func TestContextHistoryListsByCurrentWorkloadIdentity(t *testing.T) {
	f := newInvestigationFixture()
	s, r := historyService(f)
	ref := f.intent().Target
	if _, err := s.List(t.Context(), f.source(t, t.Context()), ref, []value.HistoryOrigin{value.HistoryManual}, nil, 20); err != nil {
		t.Fatal(err)
	}
	// The SQL lookup uses the resolved current UIDs, never the name.
	if r.listed.Target != f.target.Target() || r.listed.Limit != 20 || r.listed.Identity.Principal != f.actor {
		t.Fatal("history not keyed by the current workload identity", r.listed)
	}
	f.missing = true
	if _, err := s.List(t.Context(), f.source(t, t.Context()), ref, []value.HistoryOrigin{value.HistoryManual}, nil, 20); err == nil {
		t.Fatal("history listed for a workload that does not resolve")
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
