package fleet

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
)

// InitialInstallationReadAuthority proves the current administrator and exact
// immutable startup inputs without requiring the old activation Pod to run.
// It is not the witness consumer, pristine database check or recovery gate.
type InitialInstallationReadAuthority interface {
	CheckInitialInstallationRead(context.Context, value.InstallationWitnessScope, artifact.Digest) (time.Time, error)
}

type InitialInstallationDisposition string

const (
	// Missing is only an observation. A concurrent or delayed writer can still
	// create an attempt. It is never permission for a replacement or new effect.
	InitialInstallationMissing   InitialInstallationDisposition = "missingObservation"
	InitialInstallationPrepared  InitialInstallationDisposition = "prepared"
	InitialInstallationAudited   InitialInstallationDisposition = "audited"
	InitialInstallationActivated InitialInstallationDisposition = "activatedHistorical"
)

// A retained result says nothing about current RecoveryReady, writer quiescence
// or retired credentials. Original claim/audit identities are never refreshed.
type InitialInstallationObservation struct {
	Disposition  InitialInstallationDisposition
	Record       *audit.InitialInstallation
	AuditReceipt *audit.Receipt
	ActivatedAt  time.Time
	ValidUntil   time.Time `json:"-"`
}

type InitialInstallationHistory interface {
	ObserveInitialInstallation(context.Context) (InitialInstallationObservation, error)
}
