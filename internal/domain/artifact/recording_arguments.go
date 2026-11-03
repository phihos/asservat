package artifact

// RecordingArguments is the accepted immutable argument mechanism tuple. The
// protected compiler resolves the engine and ABI table independently; this DTO
// never resolves a caller-provided program or grants observation authority.
// Names/rate/thread/output ceilings remain in Recording.Syscalls. Admission and
// the node independently check the current argument accounting rule and pins.
type RecordingArguments struct {
	ProgramDigest, DefinitionDigest, AccountingRule    Digest
	MaxProbeBytes, MaxBytesPerEvent, MaxBytesPerSecond int64
	CaptureBuffers                                     bool
}

func (a *RecordingArguments) Valid() bool {
	return a != nil && a.ProgramDigest != (Digest{}) && a.DefinitionDigest != (Digest{}) && a.AccountingRule != (Digest{}) &&
		(a.MaxProbeBytes == 256 || a.MaxProbeBytes == 512) && a.MaxBytesPerEvent >= 1 && a.MaxBytesPerEvent <= 4096 &&
		(a.MaxProbeBytes == 256 || a.MaxBytesPerEvent >= 128) && a.MaxBytesPerSecond >= a.MaxProbeBytes && a.MaxBytesPerSecond <= 1<<30
}
