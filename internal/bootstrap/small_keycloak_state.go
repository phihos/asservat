package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// SmallKeycloakStateStore belongs only to finite installation preparation.
// DatabaseStateExists must report retained database state, not server readiness.
type SmallKeycloakStateStore interface {
	Read(context.Context) (*core.Secret, error)
	Create(context.Context, *core.Secret) (*core.Secret, error)
	DatabaseStateExists(context.Context) (bool, error)
}

type SmallKeycloakPreparation struct {
	store    SmallKeycloakStateStore
	settings contracts.SmallKeycloakSettings
}

func NewSmallKeycloakPreparation(store SmallKeycloakStateStore, s contracts.SmallKeycloakSettings) (*SmallKeycloakPreparation, error) {
	if store == nil || !validSmallKeycloakSettings(s) {
		return nil, mounts.ErrUnavailable
	}
	s.MCPRedirectURIs = slices.Clone(s.MCPRedirectURIs)
	return &SmallKeycloakPreparation{store: store, settings: s}, nil
}

func clearSmallKeycloakSecret(v *core.Secret) {
	if v != nil {
		for _, b := range v.Data {
			clear(b)
		}
	}
}

func (s *SmallKeycloakPreparation) retained(v *core.Secret) bool {
	return ValidateSmallKeycloakMaterial(s.settings, v) == nil && authorization.UUID(string(v.UID)) && v.ResourceVersion != ""
}

// Prepare creates once. Uncertain CREATE is followed by one exact GET against
// this call's original private bytes; it never causes a second CREATE.
func (s *SmallKeycloakPreparation) Prepare(ctx context.Context) (contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	if s == nil || ctx == nil || ctx.Err() != nil {
		return zero, mounts.ErrUnavailable
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	old, err := s.store.Read(ctx)
	if err == nil {
		defer clearSmallKeycloakSecret(old)
		if !s.retained(old) || ctx.Err() != nil {
			return zero, mounts.ErrUnavailable
		}
		return contracts.WorkerObjectReference{Name: old.Name, UID: string(old.UID)}, nil
	}
	clearSmallKeycloakSecret(old)
	if !apierrors.IsNotFound(err) || ctx.Err() != nil {
		return zero, mounts.ErrUnavailable
	}
	exists, err := s.store.DatabaseStateExists(ctx)
	if err != nil || exists || ctx.Err() != nil {
		return zero, mounts.ErrUnavailable
	}
	material, err := BuildSmallKeycloakMaterial(s.settings, rand.Reader)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	defer clearSmallKeycloakSecret(material)
	request := material.DeepCopy()
	defer clearSmallKeycloakSecret(request)
	actual, createErr := s.store.Create(ctx, request)
	if createErr != nil {
		clearSmallKeycloakSecret(actual)
		actual, err = s.store.Read(ctx)
		if err != nil {
			clearSmallKeycloakSecret(actual)
			return zero, mounts.ErrUnavailable
		}
	}
	defer clearSmallKeycloakSecret(actual)
	if !s.retained(actual) || ctx.Err() != nil || len(actual.Data) != len(material.Data) {
		return zero, mounts.ErrUnavailable
	}
	for key, value := range material.Data {
		if !bytes.Equal(value, actual.Data[key]) {
			return zero, mounts.ErrUnavailable
		}
	}
	return contracts.WorkerObjectReference{Name: actual.Name, UID: string(actual.UID)}, nil
}
