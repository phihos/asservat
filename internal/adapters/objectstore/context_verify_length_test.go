package objectstore

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

type lengthFailureCheck struct{}

func (lengthFailureCheck) Write([]byte) error { return nil }
func (lengthFailureCheck) Close() error       { return artifact.ErrIntegrity }

func TestContextVerificationReturnsOnlyCompleteNativeLength(t *testing.T) {
	native := profileSummaryNative(t)
	defer clear(native)
	for _, mode := range []string{"complete", "whole-file-hash", "semantic-check", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			f := prepareProfileEncryptedFixture(t, dir, bytes.NewReader(native), mode == "whole-file-hash")
			reads := map[string]int{}
			var mu sync.Mutex
			verifier, keys, _, _ := profileEncryptedVerifier(t, dir, f, false, func(role string) { mu.Lock(); reads[role]++; mu.Unlock() })
			ctx := t.Context()
			if mode == "semantic-check" {
				verifier.WithStreamCheck(artifact.PprofArtifact, func(artifact.ContextExpectation) StreamCheck { return lengthFailureCheck{} })
			}
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			size, err := verifier.VerifyContext(ctx, f.Source.Expectation, f.Source.Copies)
			if mode == "complete" {
				mu.Lock()
				frames := int((int64(len(native)) + artifact.FrameBytes - 1) / artifact.FrameBytes)
				if reads["commit"] != 1 || reads["manifest"] != 1 || reads["index"] != 1 || reads["data"] != frames {
					t.Error("native size caused duplicate object reads", reads)
				}
				mu.Unlock()
				if err != nil || size != int64(len(native)) || size == f.Source.Expectation.Registration.NativeLimit || keys.calls != 3 {
					t.Fatal("verified length needs extra read/keys or uses admitted maximum", size, len(native), keys.calls, err)
				}
			} else {
				if err == nil || size != 0 {
					t.Fatal("failed verification supplied usable length", size, err)
				}
				if mode == "cancelled" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			}
		})
	}
}
