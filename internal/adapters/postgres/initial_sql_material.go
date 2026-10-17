package postgres

import (
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
)

// NewInitialSQLMaterial is used only by the trusted bootstrap that durably
// retains its original private bytes before supplying their immutable Secret
// pin. It never creates SQL roles or regenerates missing unresolved material.
func NewInitialSQLMaterial(installation, request string) (contracts.InitialSQLMaterial, error) {
	if !authorization.UUID(request) {
		return contracts.InitialSQLMaterial{}, value.ErrInvalid
	}
	// Reuse the established independent crypto/rand password generator. Its
	// temporary local interval is deliberately not stored or used as authority.
	p, err := NewInitialSQLCredentials(installation, time.Now())
	if err != nil {
		return contracts.InitialSQLMaterial{}, err
	}
	return contracts.InitialSQLMaterial{Format: contracts.InitialSQLMaterialFormat, InstallationID: installation, RequestID: request, PreparationPassword: p.Preparation.Password, AuditPassword: p.Audit.Password, ActivationPassword: p.Activation.Password}, nil
}

// BindInitialSQLMaterial reconstructs ADR100 bytes from the retained material
// and original public interval. This codec grants no permission to provision;
// the caller must use the durably accepted exact binding and current guards.
// Expired intervals remain reconstructable for exact lookup and retirement.
func BindInitialSQLMaterial(m contracts.InitialSQLMaterial, installation, request string, notBefore, notAfter time.Time) (InitialSQLCredentials, error) {
	if m.Format != contracts.InitialSQLMaterialFormat || !authorization.UUID(request) || m.InstallationID != installation || m.RequestID != request || notBefore.Location() != time.UTC || notAfter.Location() != time.UTC {
		return InitialSQLCredentials{}, value.ErrInvalid
	}
	p := InitialSQLCredentials{InstallationID: installation, NotBefore: notBefore, NotAfter: notAfter, Preparation: InitialSQLLogin{initialRoleName(installation, "prepare"), m.PreparationPassword}, Audit: InitialSQLLogin{initialRoleName(installation, "audit"), m.AuditPassword}, Activation: InitialSQLLogin{initialRoleName(installation, "activate"), m.ActivationPassword}}
	if !p.valid() {
		return InitialSQLCredentials{}, value.ErrInvalid
	}
	return p, nil
}
