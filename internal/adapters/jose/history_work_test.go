package jose

import (
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
	"testing"
	"time"
)

func TestHistoryWorkUsesDistinctPurposeAndActualSelectedExecutor(t *testing.T) {
	base, r, trust, key, now := apiWorkFixture(t)
	e := capture.HistoryExpectation{RootID: base.Channel.RootID, CaptureID: base.CaptureID, Registration: artifact.Registration{Location: artifact.Location{ClusterID: base.Target.ClusterID, ArtifactID: base.CaptureID, AttemptID: base.AttemptID}, StoreID: base.Channel.Hub.ClusterID, AllocationID: base.Channel.ExchangeID, PoolRevision: 1, AllocationRevision: 1, NativeLimit: capture.MaxHistoryParameters, AnchorAt: now.Add(-time.Second), WriteUntil: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}, SelectorKey: artifact.Digest{1}, SettingsKey: artifact.Digest{2}, MACVersion: "v1", OriginalExecutionDigest: base.ScopeDigest}
	a := capture.HistoryOperationAuthority{Expectation: e, Operation: "write", RequestID: base.Channel.Challenge, ExecutorEpoch: base.Channel.Executor.ProcessEpoch, StartedAt: *now, NotAfter: base.NotAfter, BundleDigest: artifact.Digest{3}}
	w := app.HistoryWork{Channel: base.Channel, Authority: a}
	s := apiSignatures(t, func(context.Context) (value.APIContextWorkTrust, error) { return trust, nil }, key, now)
	encoded, err := s.SignHistoryWork(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.VerifyHistoryWork(context.Background(), encoded, r)
	if err != nil || !got.Valid(*now) || got.Work.Authority != a {
		t.Fatal("history roundtrip", err)
	}
	if _, err = s.VerifyAPIContextWork(context.Background(), encoded, r); err == nil {
		t.Fatal("history signed purpose became API execution")
	}
	ordinary, err := s.SignAPIContextWork(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.VerifyHistoryWork(context.Background(), ordinary, r); err == nil {
		t.Fatal("ordinary signed work became history effect")
	}
	w.Authority.ExecutorEpoch = base.Channel.Connector.ProcessEpoch
	if _, err = s.SignHistoryWork(context.Background(), w); err == nil {
		t.Fatal("wrong executor epoch signed")
	}
	trust.Trust.Keys = nil
	if _, err = s.VerifyHistoryWork(context.Background(), encoded, r); err == nil {
		t.Fatal("removed signing key reused")
	}
}
