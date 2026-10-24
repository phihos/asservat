package kms

import (
	"errors"

	"asservat.local/asservat/internal/adapters/postgres"
)

// Only the concrete SQL reader's closed diagnostic crosses this boundary.
// Preserve the existing key-service sentinel and never retain its underlying
// configuration error, row values or arbitrary dependency FixedStep methods.
func ownerProviderConfigurationFailure(step string, cause error) error {
	var failure *postgres.OwnerConfigurationReadFailure
	if !errors.As(cause, &failure) || failure == nil {
		return ErrKeyService
	}
	return ownerProviderConfigurationError{step + "/" + failure.FixedStep()}
}

type ownerProviderConfigurationError struct{ step string }

func (e ownerProviderConfigurationError) Error() string     { return ErrKeyService.Error() }
func (e ownerProviderConfigurationError) Unwrap() error     { return ErrKeyService }
func (e ownerProviderConfigurationError) FixedStep() string { return e.step }

func ownerProviderProofFailure(step string, cause error) string {
	var configuration ownerProviderConfigurationError
	if errors.As(cause, &configuration) {
		return step + "/" + configuration.FixedStep()
	}
	return step
}
