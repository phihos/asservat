package framed

import (
	"bytes"
	"context"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

// This regression also builds against the original push reader. It must not
// fetch another frame before giving the application's next delivery check the
// opportunity to refuse the last buffered chunk of the current frame.
func TestReaderDenialAtFrameBoundaryDoesNotReadNextFrame(t *testing.T) {
	l, k, data, index := encode(t, bytes.Repeat([]byte{31}, int(artifact.FrameBytes)+17))
	r := open(t, l, k, data, index)
	out := &destination{denyAt: int(artifact.FrameBytes) / artifact.DeliveryBytes}
	if err := r.Read(context.Background(), 0, l.NativeBytes, out); err == nil {
		t.Fatal("delivery denial ignored")
	}
	if data.reads != 1 || index.reads != 1 || out.Len() != int(artifact.FrameBytes)-artifact.DeliveryBytes {
		t.Fatalf("read ahead of denied frame-boundary delivery: data=%d index=%d output=%d", data.reads, index.reads, out.Len())
	}
}
