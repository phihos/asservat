package objectstore

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime/trace"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
)

type lengthFailureCheck struct{}

func (lengthFailureCheck) Write([]byte) error { return nil }
func (lengthFailureCheck) Close() error       { return artifact.ErrIntegrity }

type acquisitionFinalCheck struct{ close func() error }

func (acquisitionFinalCheck) Write([]byte) error { return nil }
func (c acquisitionFinalCheck) Close() error     { return c.close() }

func TestContextVerificationReturnsOnlyCompleteNativeLength(t *testing.T) {
	native := profileSummaryNative(t)
	defer clear(native)
	for _, mode := range []string{"complete", "whole-file-hash", "last-frame", "index-authentication", "semantic-check", "cancelled", "cancelled-at-final-check"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			f := prepareProfileEncryptedFixture(t, dir, bytes.NewReader(native), mode == "whole-file-hash")
			if mode == "last-frame" || mode == "index-authentication" {
				role := "data"
				if mode == "index-authentication" {
					role = "index"
				}
				path := filepath.Join(dir, role)
				ciphertext, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				ciphertext[len(ciphertext)-1] ^= 1
				if err := os.WriteFile(path, ciphertext, 0600); err != nil {
					t.Fatal(err)
				}
			}
			reads := map[string]int{}
			var mu sync.Mutex
			verifier, keys, _, _ := profileEncryptedVerifier(t, dir, f, false, func(role string) { mu.Lock(); reads[role]++; mu.Unlock() })
			ctx := t.Context()
			if mode == "semantic-check" {
				verifier.WithStreamCheck(artifact.PprofArtifact, func(artifact.ContextExpectation) StreamCheck { return lengthFailureCheck{} })
			}
			if mode == "cancelled" || mode == "cancelled-at-final-check" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				if mode == "cancelled" {
					cancel()
				} else {
					verifier.WithStreamCheck(artifact.PprofArtifact, func(artifact.ContextExpectation) StreamCheck {
						return acquisitionFinalCheck{close: func() error { cancel(); return nil }}
					})
				}
			}
			result, err := verifier.VerifyContext(ctx, f.Source.Expectation, f.Source.Copies)
			if mode == "complete" {
				mu.Lock()
				frames := int((int64(len(native)) + artifact.FrameBytes - 1) / artifact.FrameBytes)
				if reads["commit"] != 1 || reads["manifest"] != 1 || reads["index"] != 1 || reads["data"] != frames {
					t.Error("native size caused duplicate object reads", reads)
				}
				mu.Unlock()
				want := artifact.AcquisitionWindow{StartedAt: f.Source.Expectation.TriggeredAt, CompletedAt: f.Source.Expectation.TriggeredAt.Add(time.Second)}
				if err != nil || result.NativeBytes != int64(len(native)) || result.NativeBytes == f.Source.Expectation.Registration.NativeLimit || keys.calls != 3 || result.Acquisition == nil || !result.Acquisition.Equal(want) {
					t.Fatal("verified result needs extra read/keys or loses authenticated facts", result, len(native), keys.calls, err)
				}
			} else {
				if err == nil || result.NativeBytes != 0 || result.Acquisition != nil {
					t.Fatal("failed verification supplied usable length/timing", result, err)
				}
				if (mode == "cancelled" || mode == "cancelled-at-final-check") && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestProfileVerificationNormalizesAuthenticatedAcquisitionOnly(t *testing.T) {
	for _, nativeType := range []string{artifact.PprofArtifact, artifact.GoTraceArtifact, artifact.PodStatusArtifact} {
		t.Run(nativeType, func(t *testing.T) {
			handle, e, native := writerFixture(t, http.NotFoundHandler())
			handle.Close()
			defer clear(native)
			if nativeType != artifact.PodStatusArtifact {
				e.NativeType, e.DataClass, e.ActionID = nativeType, "raw", "a0123456789abcdef01234567"
				e.Profile = &artifact.GoProfileAcquisition{SourceRef: "synthetic", EndpointDigest: artifact.Digest{1}, Type: "cpu", Mode: "interval", DurationMillis: 1000}
				e.Registration.NativeLimit = artifact.MaxPprofBytes
				// Keep the synthetic one-second acquisition wholly in the past,
				// preserving the verifier's existing manifest clock check.
				e.Registration.AnchorAt = e.Registration.AnchorAt.Add(-3 * time.Second)
				e.Registration.ExpiresAt = e.Registration.ExpiresAt.Add(-3 * time.Second)
				e.Registration.DeleteBy = e.Registration.DeleteBy.Add(-3 * time.Second)
				e.TriggeredAt = e.Registration.AnchorAt.Add(time.Second).Truncate(time.Second).Add(123456789 * time.Nanosecond)
				native = comparisonEncryptedNative(t, 7)
				if nativeType == artifact.GoTraceArtifact {
					e.Profile.Type, e.Registration.NativeLimit = "runtimeTrace", artifact.MaxGoTraceBytes
					var b bytes.Buffer
					if err := trace.Start(&b); err != nil {
						t.Fatal(err)
					}
					trace.Stop()
					native = b.Bytes()
				}
			}
			dir := t.TempDir()
			copies := prepareEncryptedProjectionSource(t, dir, bytes.NewReader(native), e, false)
			f := profileEncryptedFixture{Source: evidence.NativeContextSource{Expectation: e, Copies: copies}}
			verifier, keys, _, _ := profileEncryptedVerifier(t, dir, f, false)
			result, err := verifier.VerifyContext(t.Context(), e, copies)
			if err != nil || result.NativeBytes != int64(len(native)) || keys.calls != 3 {
				t.Fatal(result, keys.calls, err)
			}
			if nativeType == artifact.PodStatusArtifact {
				if result.Acquisition != nil {
					t.Fatal("non-profile received acquisition metadata")
				}
				return
			}
			want := artifact.AcquisitionWindow{StartedAt: e.TriggeredAt.UTC().Truncate(time.Microsecond), CompletedAt: e.TriggeredAt.Add(time.Second).UTC().Truncate(time.Microsecond)}
			if result.Acquisition == nil || !result.Acquisition.Valid() || !result.Acquisition.Equal(want) {
				t.Fatal("sealed nanoseconds were not normalized at the verified boundary", result)
			}
			if e.TriggeredAt.Nanosecond() != 123456789 {
				t.Fatal("accepted source precision changed")
			}
			// Reopen the same sealed manifest independently: normalization changes
			// only verified display metadata, never sealed/native source bytes.
			_, manifest, err := verifier.open(t.Context(), e, copies, e.Registration.WriteUntil)
			if err != nil || !manifest.StartedAt.Equal(e.TriggeredAt) || manifest.StartedAt.Nanosecond() != 123456789 {
				t.Fatal("sealed precision lost", err)
			}
		})
	}
}
