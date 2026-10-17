package artifact

// FramedReadWork separates object bytes from native frame decoding. Pages also
// bound index JSON work (at most PageBytes decoded bytes per page). It excludes
// manifest/key opening, output, transport, audit and repeated independent reads.
// These are arithmetic values, not permission or a refundable spend receipt.
type FramedReadWork struct {
	DataBytes, IndexBytes, DecodedBytes int64
	Frames, Pages                       int64
}

// RangeReadWork bounds one sequential read of the exact native selection. Each
// overlapping page and whole frame is read once, including boundary frames.
// DataBytes is conservative until the authenticated index is opened; index bytes,
// decoded native bytes and counts are exact for a successful read. A separate
// cursor/window that overlaps these frames must reserve their work again.
func (l Layout) RangeReadWork(offset, size int64) (FramedReadWork, error) {
	if l.Validate() != nil || offset < 0 || size < 0 || offset > l.NativeBytes || size > l.NativeBytes-offset || (size == 0 && l.NativeBytes != 0) {
		return FramedReadWork{}, ErrInvalid
	}
	// All arithmetic below follows validation against the 1 TiB format bound;
	// in particular offset+size and frame rounding cannot overflow int64.
	first, last := offset/FrameBytes, (offset+size-1)/FrameBytes
	if l.NativeBytes == 0 {
		first, last = 0, 0 // The empty file still authenticates one frame/page.
	}
	var work FramedReadWork
	for _, p := range l.Pages {
		lo, hi := max(first, int64(p.FirstFrame)), min(last+1, int64(p.FirstFrame+p.FrameCount))
		if lo >= hi {
			continue
		}
		frames := hi - lo
		decoded := min(hi*FrameBytes, l.NativeBytes) - lo*FrameBytes
		work.Frames += frames
		work.Pages++
		work.DecodedBytes += decoded
		work.IndexBytes += p.IndexBytes
		// The selected ciphertext cannot exceed either this entire page's data
		// span or the selected frames' native sizes plus their fixed overhead.
		work.DataBytes += min(p.DataBytes, decoded+frames*CipherOverhead)
	}
	return work, nil
}
