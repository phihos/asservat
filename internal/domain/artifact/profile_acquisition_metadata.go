package artifact

// ProfileAcquisitionMetadata contains accepted request parameters and optional
// authenticated acquisition timing. It carries no endpoint, native data or
// process attribution. A nil window means legacy timing is unknown.
type ProfileAcquisitionMetadata struct {
	Type, Mode     string
	DurationMillis int64
	ForceGC        bool
	Acquisition    *AcquisitionWindow
}
