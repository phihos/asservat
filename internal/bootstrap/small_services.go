package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

const SmallServicesRoot = "/run/asservat/small-services"

type smallServicesFailure string

func (s smallServicesFailure) Error() string { return string(s) }
func (s smallServicesFailure) Unwrap() error { return mounts.ErrUnavailable }

// Diagnostics name a fixed failing stage without provider response bodies or
// credentials. They help operators fix the first failed boundary in one pass.
func SmallServicesDiagnostic(err error) string {
	var stage smallServicesFailure
	if errors.As(err, &stage) {
		switch stage {
		case "KeycloakStateUnavailable", "PostgresStateUnavailable", "ObjectStoreStateUnavailable":
			return "small-services-prepare: " + string(stage) + "; inspect the selected service's original private state and retained data"
		}
	}
	return "small-services-prepare: InputUnavailable; check the selected services, trusted bootstrap namespace, projected inputs and Kubernetes credentials"
}

// Order matters on a fresh installation: Keycloak must persist its original
// identity before PostgreSQL can initialize its database. On retries each
// provider's create-once adapter validates the retained original state.
func prepareSmallServices(ctx context.Context, operations ...func(context.Context) error) error {
	for _, prepare := range operations {
		if ctx.Err() != nil {
			return mounts.ErrUnavailable
		}
		if prepare != nil {
			if err := prepare(ctx); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func runSmallServicesPreparation(ctx context.Context, files *os.Root) error {
	if ctx == nil || ctx.Err() != nil || files == nil {
		return mounts.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	raw, err := mounts.Read(ctx, files, "preparation.json", contracts.SmallServicesMaxBytes)
	if err != nil {
		return mounts.ErrUnavailable
	}
	p, err := contracts.DecodeSmallServicesPreparation(bytes.NewReader(raw))
	clear(raw)
	pg := contracts.SmallPostgresPlan{Format: contracts.SmallPostgresFormat, Namespace: p.Namespace, Name: p.Name, Keycloak: p.Keycloak != nil && !p.KeycloakExternalDatabase}
	if err != nil || p.Format != contracts.SmallServicesFormat || !pg.Valid() || p.Namespace == "default" || strings.HasPrefix(p.Namespace, "kube-") {
		return mounts.ErrUnavailable
	}
	if !p.Postgres && p.Keycloak == nil && p.ObjectStore == nil || !ownerEndpoint(p.Kubernetes.Endpoint) || p.KeycloakExternalDatabase && p.Keycloak == nil {
		return mounts.ErrUnavailable
	}
	if k := p.Keycloak; k != nil {
		if k.Namespace != p.Namespace || k.SecretName != p.Name+"-keycloak-state" || !validSmallKeycloakSettings(*k) {
			return mounts.ErrUnavailable
		}
		if !p.KeycloakExternalDatabase && (!p.Postgres || k.Database != (contracts.SmallKeycloakDatabase{Host: pg.Host(), Port: 5432, Database: "keycloak", Username: "keycloak"})) {
			return mounts.ErrUnavailable
		}
	}
	if store := p.ObjectStore; store != nil && (!store.Valid() || store.Namespace != p.Namespace || store.Name != p.Name) {
		return mounts.ErrUnavailable
	}
	ca := []byte(p.Kubernetes.RootsPEM)
	if len(ca) == 0 {
		ca, err = mounts.Read(ctx, files, "kube-ca.crt", 32<<10)
		if err != nil {
			return mounts.ErrUnavailable
		}
	}
	roots, err := providerconfig.TrustRootsPEM(ca, time.Now())
	if err != nil {
		return mounts.ErrUnavailable
	}
	in := &providerInputs{files: files, oneShot: true, kubernetesEndpoint: contracts.OwnerProviderEndpoint{Endpoint: p.Kubernetes.Endpoint, Roots: roots}}
	defer in.closeHTTP()
	config := in.kubernetes("administrator-token")
	var prepareKC, preparePG, prepareS3 func(context.Context) error
	if p.Keycloak != nil {
		databaseState := pg.StateSecretName()
		var externalPresence func(context.Context) (bool, error)
		if p.KeycloakExternalDatabase {
			d := p.Keycloak.Database
			databaseState = ""
			// Read private inputs only if the original Keycloak state is absent
			// and no retained Deployment exists. Replay needs neither database
			// availability nor fresh credentials, and never regenerates identity.
			externalPresence = func(ctx context.Context) (bool, error) {
				ca, e := mounts.Read(ctx, files, "keycloak-database-ca.crt", 32<<10)
				if e != nil {
					return false, mounts.ErrUnavailable
				}
				roots, e := providerconfig.TrustRootsPEM(ca, time.Now())
				if e != nil {
					return false, mounts.ErrUnavailable
				}
				password, e := mounts.Read(ctx, files, "keycloak-database-password", 4096)
				if e != nil {
					return false, mounts.ErrUnavailable
				}
				defer clear(password)
				probe, e := postgres.NewSmallKeycloakDatabasePresence(contracts.OwnerPostgresEndpoint{Host: d.Host, Port: d.Port, Database: d.Database, Roots: roots, MaxConnections: 1}, contracts.OwnerSQLCredential{Username: d.Username, Password: string(password)})
				if e != nil {
					return false, mounts.ErrUnavailable
				}
				return probe.Exists(ctx)
			}
		}
		store, e := kube.NewSmallKeycloakStateStore(config, *p.Keycloak, databaseState, p.Name+"-keycloak", externalPresence)
		if e != nil {
			return mounts.ErrUnavailable
		}
		service, e := NewSmallKeycloakPreparation(store, *p.Keycloak)
		if e != nil {
			return mounts.ErrUnavailable
		}
		prepareKC = func(ctx context.Context) error {
			if _, err := service.Prepare(ctx); err != nil {
				return smallServicesFailure("KeycloakStateUnavailable")
			}
			return nil
		}
	}
	if p.Postgres {
		service, e := kube.NewSmallPostgresPreparation(config, pg)
		if e != nil {
			return mounts.ErrUnavailable
		}
		preparePG = func(ctx context.Context) error {
			if _, err := service.Prepare(ctx); err != nil {
				return smallServicesFailure("PostgresStateUnavailable")
			}
			return nil
		}
	}
	if p.ObjectStore != nil {
		service, e := kube.NewSmallSeaweedPreparation(config, *p.ObjectStore)
		if e != nil {
			return mounts.ErrUnavailable
		}
		prepareS3 = func(ctx context.Context) error {
			state, err := service.Prepare(ctx)
			// Preparation persists this capability in the private provider seed.
			// This hook does not disclose it or activate any installation/bucket.
			state.Admin.SecretAccessKey = ""
			if err != nil {
				return smallServicesFailure("ObjectStoreStateUnavailable")
			}
			return nil
		}
	}
	return prepareSmallServices(ctx, prepareKC, preparePG, prepareS3)
}

// RunSmallServicesPreparation runs only in the finite trusted provider hook.
func RunSmallServicesPreparation(ctx context.Context) error {
	if disableWorkerCoreDumps() != nil {
		return mounts.ErrUnavailable
	}
	files, err := os.OpenRoot(SmallServicesRoot)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer files.Close()
	return runSmallServicesPreparation(ctx, files)
}
