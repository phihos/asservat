package objectstore

import (
	"asservat.local/asservat/internal/adapters/packets"
	q "asservat.local/asservat/internal/domain/analysis"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPacketQueryEncryptedTailAndCancellationAfterLogicalStop(t *testing.T) {
	for _, mode := range []string{"complete", "malformed-tail", "bad-stats", "whole-hash", "ciphertext", "cancel", "unconfigured", "over-cap"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			f := packetEncryptedFixtureSource(t, dir, mode, true)
			f.Scope.DisplayVersion = q.PacketQueryDisplayVersion
			f.Scope.RawGrantID = f.Scope.RootID
			f.Scope.PacketQuery, _ = (q.PacketQuerySelection{Fields: []q.PacketQueryField{q.PacketIndex}, MaxPackets: 1, MaxScanBytes: 1 << 20}).Window()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			verifier, keys, entered, unblock := profileEncryptedVerifier(t, dir, f, mode == "cancel")
			r, err := NewContextProjectionReader(verifier.store)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "unconfigured" {
				r.ServePacketQueries(packets.QueryPCAPNG)
			}
			if mode == "ciphertext" {
				p := filepath.Join(dir, "data")
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				b[32] ^= 1
				if err = os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			type answer struct {
				result q.ProjectionResult
				err    error
			}
			done := make(chan answer, 1)
			go func() {
				result, err := r.ReadProjectionNative(ctx, f.Source, f.Scope, keys, time.Now().Add(10*time.Second))
				done <- answer{result, err}
			}()
			if mode == "cancel" {
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("never entered source", ctx.Err())
				}
				cancel()
				unblock()
			}
			select {
			case got := <-done:
				if mode == "complete" {
					if got.err != nil || got.result.PacketQuery == nil || len(got.result.PacketQuery.Rows) != 1 || !got.result.PacketQuery.RowLimitReached {
						t.Fatal(got.err)
					}
				} else if got.err == nil || got.result.PacketQuery != nil {
					t.Fatal("fault after logicalstop disclosed page", mode, got.err)
				}
				if mode == "unconfigured" && keys.calls != 0 {
					t.Fatal("unconfigured spent keys")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("reader not joined")
			}
		})
	}
}
