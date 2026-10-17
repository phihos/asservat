package framed

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
	"time"
)

func TestDownloadStopAuditExactDecisionAndOneWrap(t *testing.T) {
	k := &countingKeys{testKeys: keys(t)}
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := artifact.DownloadStopDecision{Protocol: artifact.DownloadStopProtocol, RootID: "00000000-0000-4000-8000-000000000001", DownloadID: "00000000-0000-4000-8000-000000000002", RequestID: "00000000-0000-4000-8000-000000000003", StoreID: "00000000-0000-4000-8000-000000000004", Actor: identity.Principal{Issuer: "https://id.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human}, KeyDigest: artifact.Digest{1}, State: "Cancelled", RequestedAt: now, WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Hour)}
	b, e := SealDownloadStop(context.Background(), k, d)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(b)
	if e = VerifyDownloadStop(context.Background(), k, d, b); e != nil || k.wraps != 1 || k.unwraps != 1 || int64(len(b)) > artifact.DownloadStopCipherLimit {
		t.Fatal("wrong provider accounting", e, k.wraps, k.unwraps)
	}
	for _, mutate := range []func(*artifact.DownloadStopDecision){func(x *artifact.DownloadStopDecision) { x.Actor.ClientID = "another" }, func(x *artifact.DownloadStopDecision) { x.KeyDigest[0]++ }, func(x *artifact.DownloadStopDecision) { x.RequestedAt = x.RequestedAt.Add(time.Microsecond) }, func(x *artifact.DownloadStopDecision) { x.State = "AlreadyTerminal" }} {
		changed := d
		mutate(&changed)
		if VerifyDownloadStop(context.Background(), k, changed, b) == nil {
			t.Fatal("different frozen stop verified")
		}
	}
}
