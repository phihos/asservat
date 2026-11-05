package jose

import (
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
	"testing"
	"time"
)

func TestProcessStopSignedControlKeepsExactWriterAndPurpose(t *testing.T) {
	base, receiver, trust, key, now := apiWorkFixture(t)
	signer := apiSignatures(t, func(context.Context) (value.APIContextWorkTrust, error) { return trust, nil }, key, now)
	stop := collector.ProcessStop{RootID: base.Channel.RootID, ClusterID: base.Channel.Connector.Binding.ClusterID, CaptureID: base.CaptureID, AttemptID: base.AttemptID, WriterPodUID: base.Channel.Executor.PodUID, WriterEpoch: base.Channel.Executor.ProcessEpoch, ExpectationDigest: artifact.Digest{1}, WriteUntil: now.Add(time.Minute)}
	work := app.SourceWork{Channel: base.Channel, StopProcesses: &stop, StopIssuedAt: *now, NotAfter: now.Add(5 * time.Second)}
	signed, err := signer.SignSourceWork(t.Context(), work)
	if err != nil {
		t.Fatal(err)
	}
	got, err := signer.VerifySourceWork(t.Context(), signed, receiver)
	if err != nil || got.Work.StopProcesses == nil || !got.Work.StopProcesses.Equal(stop) || got.Work.StopProfile != nil {
		t.Fatal("distinct process control lost", err)
	}
	if _, err := signer.VerifyAPIContextWork(t.Context(), signed, receiver); err == nil {
		t.Fatal("stop became acquisition")
	}
	for _, mode := range []string{"writer", "mixed-profile", "renewed-time"} {
		bad := work
		changed := stop
		bad.StopProcesses = &changed
		switch mode {
		case "writer":
			changed.WriterEpoch = base.CaptureID
			changed.WriterPodUID = "22222222-2222-4222-8222-222222222222"
		case "mixed-profile":
			bad.StopProfile = &collector.ProfileStop{}
		case "renewed-time":
			bad.NotAfter = now.Add(6 * time.Second)
		}
		if _, err := signer.SignSourceWork(t.Context(), bad); err == nil {
			t.Fatal("invalid signed process control", mode)
		}
	}
}
