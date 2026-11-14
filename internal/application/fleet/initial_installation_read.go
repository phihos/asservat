package fleet

type InitialInstallationDisposition string

const (
	// Missing is only an observation. A concurrent or delayed writer can still
	// create an attempt. It is never permission for a replacement or new effect.
	InitialInstallationMissing  InitialInstallationDisposition = "missingObservation"
	InitialInstallationPrepared InitialInstallationDisposition = "prepared"
	InitialInstallationAudited  InitialInstallationDisposition = "audited"
)
