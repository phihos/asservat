package fleet

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
	"time"
)

type InitialInstallationPreparation interface {
	PrepareInitialInstallation(context.Context, value.InstallationWitness, value.Administration) (audit.InitialInstallation, error)
}
type InitialInstallationActivation interface {
	ActivateInitialInstallation(context.Context, value.InstallationWitness, value.Administration) error
}

// InitialInstaller composes protected input, a one-use external witness, an
// atomic eligible-database check and independently verified encrypted audit.
// It is never a restore/restart coordinator or a public permission endpoint.
type InitialInstaller struct {
	Witness          InstallationWitnessReader
	Consume          InstallationWitnessConsumer
	Administration   AdministrationReader
	Preparation      InitialInstallationPreparation
	Objects          auditapp.InitialInstallationWriter
	Acknowledgements auditapp.InitialInstallationAcknowledgements
	Activation       InitialInstallationActivation
	Now              func() time.Time
}

func (s InitialInstaller) Activate(ctx context.Context) (audit.InitialInstallation, error) {
	var zero audit.InitialInstallation
	if ctx == nil || s.Witness == nil || s.Consume == nil || s.Administration == nil || s.Preparation == nil || s.Objects == nil || s.Acknowledgements == nil || s.Activation == nil || s.Now == nil {
		return zero, value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	w, err := s.Witness.ReadInstallationWitness(ctx)
	if err != nil {
		return zero, err
	}
	a, err := s.Administration.FleetAdministration(ctx)
	if err != nil {
		return zero, err
	}
	r, err := s.Preparation.PrepareInitialInstallation(ctx, w, a)
	if err != nil {
		return zero, err
	}
	if !r.Valid() || r.Scope != w.Scope || r.Claim.FleetSource != a.Revision || !r.Claim.Current(s.Now()) {
		return zero, value.ErrDenied
	}
	consumed, err := s.Consume.ConsumeInstallationWitness(ctx, r.Claim)
	if err != nil {
		return zero, err
	}
	if !initialWitnessMatches(consumed, r, s.Now()) {
		return zero, value.ErrDenied
	}
	receipt, err := s.Objects.WriteInitialInstallation(ctx, r)
	if err != nil {
		return zero, err
	}
	if !receipt.ValidInitialInstallation(r.Scope.InstallationID, r.Claim.ID) {
		return zero, value.ErrDenied
	}
	if err = s.Acknowledgements.AcknowledgeInitialInstallation(ctx, r, receipt); err != nil {
		return zero, err
	}
	// Provider I/O may exceed observation freshness. Read again without renewing
	// the attempt, claim deadline, pins or accepted source revision.
	w, err = s.Witness.ReadInstallationWitness(ctx)
	if err != nil {
		return zero, err
	}
	a, err = s.Administration.FleetAdministration(ctx)
	if err != nil {
		return zero, err
	}
	if !initialWitnessMatches(w, r, s.Now()) || !a.Valid(s.Now()) || a.Suspended || a.InstallationID != r.Scope.InstallationID || a.IssuerEpoch != r.Scope.IssuerEpoch || a.Revision != r.Claim.FleetSource || ctx.Err() != nil {
		return zero, value.ErrDenied
	}
	if err = s.Activation.ActivateInitialInstallation(ctx, w, a); err != nil {
		return zero, err
	}
	return r, nil
}

func initialWitnessMatches(w value.InstallationWitness, r audit.InitialInstallation, now time.Time) bool {
	return w.Valid(now) && w.Scope == r.Scope && w.Claim != nil && w.Claim.Same(r.Claim) && r.Claim.Current(now)
}
