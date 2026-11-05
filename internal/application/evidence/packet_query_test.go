package evidence

import (
	q "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"io"
	"testing"
	"time"
)

func TestPacketQueryFinalAuthenticationAndClosure(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, mode := range []string{"complete", "partial", "missing-final", "changed-final", "cancel-read", "cancel-close", "wrong-mode"} {
			t.Run(mode+map[bool]string{false: "metadata", true: "raw"}[raw], func(t *testing.T) {
				source, scope, opened := packetReadFixture(t, raw)
				scope.DisplayVersion = q.PacketQueryDisplayVersion
				scope.PacketQuery, _ = (q.PacketQuerySelection{Fields: []q.PacketQueryField{q.PacketIndex}, MaxPackets: 100, MaxScanBytes: 1 << 20}).Window()
				if raw {
					scope.RawGrantID = scope.RootID
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				switch mode {
				case "missing-final":
					opened.noFinal = true
				case "changed-final":
					opened.afterRead = func() { opened.metadata.SHA256[0] ^= 1 }
				case "cancel-read":
					opened.afterRead = cancel
				case "cancel-close":
					opened.cancelClose = cancel
				}
				callback := func(ctx context.Context, r io.Reader, e artifact.ContextExpectation, a, b time.Time, s q.PacketQuerySelection) (q.PacketQueryResult, error) {
					if mode != "partial" {
						if _, err := io.Copy(io.Discard, r); err != nil {
							return q.PacketQueryResult{}, err
						}
					}
					out := q.PacketQueryResult{CaptureMode: "networkHeaders", Fields: s.Fields, Rows: [][]q.PacketQueryCell{}}
					if raw {
						out.CaptureMode = "rawPackets"
					}
					if mode == "wrong-mode" {
						out.CaptureMode = "invalid"
					}
					return out, nil
				}
				result, err := ReadPacketQuery(ctx, opened, source, scope, callback)
				if mode == "complete" {
					if err != nil || result.PacketQuery == nil || !result.Valid(scope) {
						t.Fatal("authenticatedquery", err)
					}
				} else if err == nil || result.PacketQuery != nil {
					t.Fatal("partial/faultresultescaped", mode, err)
				}
				if opened.closes != 1 {
					t.Fatal("close count", opened.closes)
				}
			})
		}
	}
}
