package evidence

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

type packetSourceFixture struct {
	*syscallSourceFixture
	closes      int
	cancelClose context.CancelFunc
}

func (s *packetSourceFixture) Close() {
	s.closes++
	s.summarySourceFixture.Close()
	if s.cancelClose != nil {
		s.cancelClose()
	}
}
func packetReadFixture(t *testing.T, raw ...bool) (NativeContextSource, query.ContextProjectionScope, *packetSourceFixture) {
	t.Helper()
	source, scope, opened := syscallProjectionFixture(t, false, query.SyscallSummaryView)
	source.Expectation.NativeType = artifact.PCAPNGArtifact
	source.Expectation.Recording = &artifact.Recording{Kind: "packetCapture", Profile: "networkHeaders", Composition: []byte("{}"), DurationMillis: 1000, MaxBytes: artifact.RecordingNativeLimit, Snaplen: artifact.RecordingSnaplen}
	scope.NativeType, scope.SourceFormat, scope.DisplayVersion = artifact.PCAPNGArtifact, artifact.PCAPNGFormat, query.PacketSummaryDisplayVersion
	if len(raw) > 0 && raw[0] {
		source.Expectation.NativeType, source.Expectation.DataClass = artifact.RawPCAPNGArtifact, "raw"
		source.Expectation.Recording.Profile = "rawPackets"
		scope.NativeType, scope.SourceFormat, scope.DisplayVersion = artifact.RawPCAPNGArtifact, artifact.RawPCAPNGFormat, query.RawPacketSummaryDisplayVersion
	}
	scope.Syscalls = query.SyscallWindow{}
	opened.metadata = expectedNativeMetadata(source, 2*artifact.DeliveryBytes+17, artifact.Digest{1})
	if !source.Valid(scope.Version) || !scope.Valid() {
		t.Fatal("synthetic packet scope/source invalid", source.Expectation.Validate())
	}
	return source, scope, &packetSourceFixture{syscallSourceFixture: opened}
}
func consumePacketSummary(ctx context.Context, r io.Reader, e artifact.ContextExpectation, from, until time.Time) (query.PacketSummary, error) {
	_, err := io.Copy(io.Discard, r)
	summary := query.PacketSummary{CaptureMode: "networkHeaders", DropReporting: "unavailable", Conversations: []query.PacketConversation{}}
	if e.NativeType == artifact.RawPCAPNGArtifact {
		summary.CaptureMode = "rawPackets"
		summary.UnclassifiedPackets = new(int64)
	}
	return summary, err
}
func TestPacketSummaryReadRequiresFinalAuthenticationAndJoinedClose(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprint(raw), func(t *testing.T) {
			for _, mode := range []string{"current", "wrong-result-mode", "partial", "swallowed-source-error", "wrong-format", "wrong-version", "wrong-pod", "oversize", "missing-final", "short", "cancel-read", "cancel-close", "changed-final-metadata", "typed-size", "typed-size-corrupt", "wrong-counter-provenance"} {
				t.Run(mode, func(t *testing.T) {
					source, scope, opened := packetReadFixture(t, raw)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					summarize := PacketSummarizer(consumePacketSummary)
					switch mode {
					case "wrong-result-mode":
						summarize = func(ctx context.Context, r io.Reader, e artifact.ContextExpectation, a, b time.Time) (query.PacketSummary, error) {
							result, err := consumePacketSummary(ctx, r, e, a, b)
							if result.CaptureMode == "rawPackets" {
								result.CaptureMode = "networkHeaders"
								result.UnclassifiedPackets = nil
							} else {
								result.CaptureMode = "rawPackets"
								result.UnclassifiedPackets = new(int64)
							}
							return result, err
						}
					case "partial":
						summarize = func(context.Context, io.Reader, artifact.ContextExpectation, time.Time, time.Time) (query.PacketSummary, error) {
							return query.PacketSummary{CaptureMode: "networkHeaders", DropReporting: "unavailable", Conversations: []query.PacketConversation{}}, nil
						}
					case "swallowed-source-error":
						opened.noFinal = true
						summarize = func(ctx context.Context, r io.Reader, e artifact.ContextExpectation, a, b time.Time) (query.PacketSummary, error) {
							s, _ := consumePacketSummary(ctx, r, e, a, b)
							return s, nil
						}
					case "wrong-format":
						opened.metadata.Format = "rawPcapng"
					case "wrong-version":
						scope.Version[0] ^= 1
					case "wrong-pod":
						scope.PodUID = "33333333-3333-4333-8333-333333333333"
					case "oversize":
						opened.metadata.Size = artifact.RecordingNativeLimit + 1
					case "missing-final":
						opened.noFinal = true
					case "short":
						opened.short = true
					case "cancel-read":
						opened.afterRead = cancel
					case "cancel-close":
						opened.cancelClose = cancel
					case "wrong-counter-provenance":
						summarize = func(ctx context.Context, r io.Reader, e artifact.ContextExpectation, a, b time.Time) (query.PacketSummary, error) {
							result, err := consumePacketSummary(ctx, r, e, a, b)
							n := int64(0)
							result.Drops = &n
							result.DropReporting = "snapshotOutputLimit"
							return result, err
						}
					case "changed-final-metadata":
						opened.afterRead = func() { opened.metadata.SHA256[0] ^= 1 }
					case "typed-size", "typed-size-corrupt":
						summarize = func(context.Context, io.Reader, artifact.ContextExpectation, time.Time, time.Time) (query.PacketSummary, error) {
							return query.PacketSummary{}, query.ErrRecordTooLarge
						}
						opened.noFinal = mode == "typed-size-corrupt"
					}
					result, err := ReadPacketSummary(ctx, opened, source, scope, summarize)
					if mode == "current" {
						if err != nil || result.PacketSummary == nil || !result.Valid(scope) || opened.offset != opened.metadata.Size {
							t.Fatal("complete source refused", err)
						}
					} else if mode == "typed-size" {
						if err == nil || result.TooLarge || result.PacketSummary != nil || opened.offset != opened.metadata.Size {
							t.Fatal("injected size fault skipped authentication or returned a result", err)
						}
					} else if err == nil || result.PacketSummary != nil || result.TooLarge {
						t.Fatal("unauthenticated result escaped", mode, err)
					}
					if opened.closes != 1 {
						t.Fatal("source not closed exactly once", opened.closes)
					}
				})
			}
		})
	}

}
