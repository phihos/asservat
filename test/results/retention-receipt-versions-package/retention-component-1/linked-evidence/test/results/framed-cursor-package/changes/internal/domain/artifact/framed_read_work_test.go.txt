package artifact

import (
	"math"
	"testing"
)

func readWorkLayout(n int64) Layout {
	l := Layout{Format: StorageFormat, Binding: Binding{ClusterID: "00000000-0000-4000-8000-000000000001", ArtifactID: "00000000-0000-4000-8000-000000000002", AttemptID: "00000000-0000-4000-8000-000000000003", MediaType: "application/octet-stream"}, NativeBytes: n, DataKey: SealedKey{"test", "sealed"}, IndexKey: SealedKey{"test", "sealed"}}
	frames := max(int64(1), (n+FrameBytes-1)/FrameBytes)
	for first := int64(0); first < frames; first += FramesPerPage {
		count := min(int64(FramesPerPage), frames-first)
		native := min(count*FrameBytes, n-first*FrameBytes)
		p := Page{Number: len(l.Pages), FirstFrame: int(first), FrameCount: int(count), NativeOffset: first * FrameBytes, NativeBytes: native, DataOffset: l.DataBytes, DataBytes: native + count*CipherOverhead, IndexOffset: l.IndexBytes, IndexBytes: PageBytes + CipherOverhead}
		l.Pages = append(l.Pages, p)
		l.DataBytes += p.DataBytes
		l.IndexBytes += p.IndexBytes
	}
	return l
}

func TestFramedRangeWorkIncludesWholeBoundaryFrames(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		native, offset, length int64
		frames, pages, decoded int64
	}{
		{"empty", 0, 0, 0, 1, 1, 0},
		{"single", 13, 0, 1, 1, 1, 13},
		{"interior", 3 * FrameBytes, 1, 1, 1, 1, FrameBytes},
		{"boundary", 3 * FrameBytes, FrameBytes - 1, 2, 2, 1, 2 * FrameBytes},
		{"short-tail", FrameBytes + 17, FrameBytes - 1, 2, 2, 1, FrameBytes + 17},
		{"page-boundary", FrameBytes * (FramesPerPage + 1), FrameBytes*FramesPerPage - 1, 2, 2, 2, 2 * FrameBytes},
		{"maximum-tail", MaxNativeBytes, MaxNativeBytes - 1, 1, 1, 1, FrameBytes},
		{"maximum-full", MaxNativeBytes, 0, MaxNativeBytes, int64(MaxFrames), int64(MaxPages), MaxNativeBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := readWorkLayout(tc.native)
			w, err := l.RangeReadWork(tc.offset, tc.length)
			want := FramedReadWork{DataBytes: tc.decoded + tc.frames*CipherOverhead, IndexBytes: tc.pages * (PageBytes + CipherOverhead), DecodedBytes: tc.decoded, Frames: tc.frames, Pages: tc.pages}
			if err != nil || w != want {
				t.Fatalf("work=%+v want=%+v err=%v", w, want, err)
			}
		})
	}
}

func TestFramedRangeWorkUsesActualPageCeilingWithoutDiscountingDecode(t *testing.T) {
	l := readWorkLayout(2 * FrameBytes)
	l.DataBytes, l.Pages[0].DataBytes = 100, 100
	w, err := l.RangeReadWork(1, 1)
	if err != nil || w.DataBytes != 100 || w.DecodedBytes != FrameBytes || w.Frames != 1 {
		t.Fatalf("compressed range work=%+v err=%v", w, err)
	}
	// Independent selections owe boundary work each time, even within one frame.
	next, err := l.RangeReadWork(2, 1)
	if err != nil || next != w {
		t.Fatal("independent selection silently reused another cursor's work")
	}
}

func TestFramedRangeWorkRejectsOverflowAndMalformedLayout(t *testing.T) {
	for _, bounds := range [][2]int64{{-1, 1}, {0, -1}, {0, 0}, {1, math.MaxInt64}, {math.MaxInt64, 1}, {MaxNativeBytes, 1}, {MaxNativeBytes - 1, 2}} {
		if _, err := readWorkLayout(MaxNativeBytes).RangeReadWork(bounds[0], bounds[1]); err == nil {
			t.Fatalf("accepted %v", bounds)
		}
	}
	for _, mutate := range []func(*Layout){
		func(l *Layout) { l.Pages[1].NativeOffset-- },
		func(l *Layout) { l.Pages[0], l.Pages[1] = l.Pages[1], l.Pages[0] },
		func(l *Layout) { l.Pages[1] = l.Pages[0] },
		func(l *Layout) { l.IndexBytes++ },
		func(l *Layout) { l.NativeBytes = math.MaxInt64 },
	} {
		l := readWorkLayout(FrameBytes * (FramesPerPage + 1))
		mutate(&l)
		if _, err := l.RangeReadWork(0, 1); err == nil {
			t.Fatal("accepted malformed directory")
		}
	}
}
