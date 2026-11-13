package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"github.com/google/uuid"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	typed "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

// SecretsRoot holds the Helm-rendered secrets.json of the `secrets` hook Job.
const SecretsRoot = "/run/asservat/secrets"

// The in-cluster API as seen by bundled OpenBao's Kubernetes auth.
const secretsKubernetesEndpoint = "https://kubernetes.default.svc"
const serviceAccountCA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

type secretsFailure string

func (s secretsFailure) Error() string { return string(s) }
func (s secretsFailure) Unwrap() error { return mounts.ErrUnavailable }

// SecretsDiagnostic names the failing stage without Secret values.
func SecretsDiagnostic(err error) string {
	var stage secretsFailure
	if errors.As(err, &stage) {
		return "secrets: " + string(stage) + "; check the named Secret (kubectl describe secret) and the Job's Role"
	}
	return "secrets: InputUnavailable; check secrets.json, the service account token and the Kubernetes API"
}

// Order matters on a fresh installation: Keycloak must persist its original
// identity before PostgreSQL can initialize its database.
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

func validSecretsPlan(p contracts.SecretsPlan) bool {
	dns := func(name string) bool { return len(validation.IsDNS1123Subdomain(name)) == 0 }
	if p.Format != contracts.SecretsFormat || len(validation.IsDNS1123Label(p.Namespace)) != 0 || p.Namespace == "default" || strings.HasPrefix(p.Namespace, "kube-") ||
		len(p.Name) > 30 || len(validation.IsDNS1123Label(p.Name)) != 0 || p.Mode != "hub" && p.Mode != "combined" || !dns(p.IDs.Secret) ||
		p.AuditMAC != "" && p.AuditMAC != p.Name+"-audit-mac" || p.ArtifactKey != "" && p.ArtifactKey != p.Name+"-artifact-key" || p.KeycloakExternalDatabase && p.Keycloak == nil {
		return false
	}
	seen := map[string]bool{}
	for _, s := range p.SQL {
		if _, ok := contracts.SQLComponentPurposes(s.Component); !ok || seen[s.Component] || s.Secret != p.Name+"-sql-"+s.Component {
			return false
		}
		seen[s.Component] = true
	}
	if k := p.Keycloak; k != nil && (k.Namespace != p.Namespace || k.SecretName != p.Name+"-keycloak-state" || !validSmallKeycloakSettings(*k)) {
		return false
	}
	if s := p.ObjectStore; s != nil && (!s.Valid() || s.Namespace != p.Namespace || s.Name != p.Name) {
		return false
	}
	return true
}

// secretStore creates Secrets once and only ever adds missing keys.
type secretStore struct {
	api       typed.SecretInterface
	namespace string
}

func clearData(d map[string][]byte) {
	for _, v := range d {
		clear(v)
	}
}

// ensure returns the Secret's data after creating it with want, or after
// adding the keys of want it lacks. Existing values are never changed.
func (s secretStore) ensure(ctx context.Context, name string, want map[string][]byte) (map[string][]byte, error) {
	current, err := s.api.Get(ctx, name, meta.GetOptions{})
	if apierrors.IsNotFound(err) {
		object := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: s.namespace, Labels: map[string]string{"app.kubernetes.io/part-of": "asservat", "app.kubernetes.io/created-by": "asservat-secrets"}}, Type: core.SecretTypeOpaque, Data: want}
		current, err = s.api.Create(ctx, object, meta.CreateOptions{FieldValidation: "Strict"})
		if err != nil {
			// Lost reply or a concurrent run: keep whatever was stored.
			current, err = s.api.Get(ctx, name, meta.GetOptions{})
		}
	}
	if err != nil {
		return nil, secretsFailure("SecretUnavailable " + name)
	}
	missing := map[string][]byte{}
	for k, v := range want {
		if _, ok := current.Data[k]; !ok {
			missing[k] = v
		}
	}
	if len(missing) == 0 {
		return current.Data, nil
	}
	return s.patch(ctx, name, missing)
}

func (s secretStore) patch(ctx context.Context, name string, data map[string][]byte) (map[string][]byte, error) {
	body, err := json.Marshal(map[string]any{"data": data})
	if err != nil {
		return nil, secretsFailure("SecretUnavailable " + name)
	}
	defer clear(body)
	current, err := s.api.Patch(ctx, name, types.MergePatchType, body, meta.PatchOptions{FieldValidation: "Strict"})
	if err != nil {
		return nil, secretsFailure("SecretUnavailable " + name)
	}
	return current.Data, nil
}

func randomKey() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

func randomPassword() (string, error) {
	b, err := randomKey()
	defer clear(b)
	return base64.RawURLEncoding.EncodeToString(b), err
}

// sqlRoleName derives the fixed login of one runtime purpose.
func sqlRoleName(installation, purpose string) (string, bool) {
	if name, ok := postgres.PublicRuntimeRoleName(installation, purpose); ok {
		return name, true
	}
	if name, ok := postgres.ConfigurationRuntimeRoleName(installation, purpose); ok {
		return name, true
	}
	return postgres.OwnerIdentityRoleName(installation, purpose)
}

type installationIDs map[string]string

func (s secretStore) ids(ctx context.Context, p contracts.SecretsIDs) (installationIDs, error) {
	var data map[string][]byte
	var err error
	if p.Generate {
		want := map[string][]byte{}
		for _, key := range contracts.InstallationIDKeys() {
			want[key] = []byte(uuid.NewString())
		}
		data, err = s.ensure(ctx, p.Secret, want)
	} else {
		var secret *core.Secret
		if secret, err = s.api.Get(ctx, p.Secret, meta.GetOptions{}); err == nil {
			data = secret.Data
		}
	}
	if err != nil {
		return nil, secretsFailure("SecretUnavailable " + p.Secret)
	}
	out := installationIDs{}
	for _, key := range contracts.InstallationIDKeys() {
		if !authorization.UUID(string(data[key])) {
			return nil, secretsFailure("InvalidIDs " + p.Secret)
		}
		out[key] = string(data[key])
	}
	return out, nil
}

func (s secretStore) sql(ctx context.Context, installation string, entry contracts.SecretsSQL) error {
	purposes, _ := contracts.SQLComponentPurposes(entry.Component)
	want := map[string][]byte{}
	defer clearData(want)
	for _, purpose := range purposes {
		name, ok := sqlRoleName(installation, purpose)
		password, err := randomPassword()
		if !ok || err != nil {
			return secretsFailure("SQLRoleUnavailable " + purpose)
		}
		want["sql-"+purpose+".json"], _ = json.Marshal(contracts.OwnerSQLCredential{Username: name, Password: password})
	}
	data, err := s.ensure(ctx, entry.Secret, want)
	if err != nil {
		return err
	}
	defer clearData(data)
	for _, purpose := range purposes {
		name, _ := sqlRoleName(installation, purpose)
		c, err := contracts.DecodeOwnerSQLCredential(bytes.NewReader(data["sql-"+purpose+".json"]))
		if err != nil || c.Username != name || c.Password == "" {
			return secretsFailure("InvalidSQLCredential " + entry.Secret)
		}
	}
	return nil
}

func (s secretStore) auditMAC(ctx context.Context, name string) error {
	input, err := randomKey()
	account, err2 := randomKey()
	defer clear(input)
	defer clear(account)
	if err != nil || err2 != nil {
		return secretsFailure("RandomUnavailable")
	}
	version := uuid.NewString()
	data, err := s.ensure(ctx, name, map[string][]byte{contracts.AuditMACInputVersion: []byte(version + "-input/v1"), contracts.AuditMACInputKey: input, contracts.AuditMACAccountVersion: []byte(version + "-account/v1"), contracts.AuditMACAccountKey: account})
	if err != nil {
		return err
	}
	defer clearData(data)
	if len(data[contracts.AuditMACInputKey]) != 32 || len(data[contracts.AuditMACAccountKey]) != 32 || len(data[contracts.AuditMACInputVersion]) == 0 || len(data[contracts.AuditMACAccountVersion]) == 0 {
		return secretsFailure("InvalidAuditMAC " + name)
	}
	return nil
}

// artifactKeyID is the derived local artifact key ID (ADR-194 D8).
func artifactKeyID(installation string) string {
	return "asservat-" + strings.ReplaceAll(installation, "-", "") + "-artifact"
}

func (s secretStore) artifactKey(ctx context.Context, name, installation string) error {
	material, err := randomKey()
	defer clear(material)
	if err != nil {
		return secretsFailure("RandomUnavailable")
	}
	payload, err := json.Marshal(map[string]any{"format": "asservat-local-keys/v1", "installationID": installation, "purpose": "artifact", "keyID": artifactKeyID(installation), "activeVersion": 1,
		"keys": []any{map[string]any{"version": 1, "material": material}}})
	if err != nil {
		return secretsFailure("RandomUnavailable")
	}
	defer clear(payload)
	data, err := s.ensure(ctx, name, map[string][]byte{contracts.ArtifactKeySecretKey: payload})
	if err != nil {
		return err
	}
	clearData(data)
	return nil
}

// objectStore creates one credential Secret per bundled SeaweedFS principal
// and compiles the complete IAM configuration from them.
func (s secretStore) objectStore(ctx context.Context, p contracts.SecretsPlan, ids installationIDs, admin contracts.SeaweedCredential) error {
	installation, cluster, root := ids["installationID"], ids["clusterID"], ids["permissionRootID"]
	bucket := p.Name + "-audit"
	var grants []contracts.SeaweedGrant
	defer func() {
		for i := range grants {
			grants[i].Credential.SecretAccessKey = ""
		}
	}()
	for _, purpose := range contracts.ObjectStorePrincipals(p.Mode) {
		scope := installation
		if strings.HasPrefix(purpose, "regional-") {
			scope = cluster
		}
		key := contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: scope}
		generated, err := providerconfig.GenerateSeaweedCredential(key)
		if err != nil {
			return secretsFailure("ObjectStoreCredentialUnavailable " + purpose)
		}
		want, _ := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: generated.AccessKeyID, SecretAccessKey: generated.SecretAccessKey})
		name := p.Name + "-s3-" + purpose
		data, err := s.ensure(ctx, name, map[string][]byte{contracts.ObjectStoreCredentialFile: want})
		clear(want)
		if err != nil {
			return err
		}
		stored, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(data[contracts.ObjectStoreCredentialFile]))
		clearData(data)
		credential := contracts.SeaweedCredential{Principal: key, AccessKeyID: stored.AccessKeyID, SecretAccessKey: stored.SecretAccessKey}
		if err != nil || providerconfig.ValidateSeaweedCredential(credential) != nil {
			return secretsFailure("InvalidObjectStoreCredential " + name)
		}
		grant := contracts.SeaweedGrant{Credential: credential, Bucket: bucket, InstallationID: installation, ClusterID: cluster, RootID: root}
		if strings.HasSuffix(purpose, "-audit") {
			grant.Prefixes = providerconfig.SeaweedAuditPrefixes(grant)
		}
		grants = append(grants, grant)
	}
	compiled, err := providerconfig.CompileSeaweedStorage(admin, grants)
	if err != nil {
		return secretsFailure("ObjectStoreIAMUnavailable")
	}
	defer clear(compiled.Config)
	name := p.ObjectStore.IAMSecretName()
	data, err := s.ensure(ctx, name, map[string][]byte{providerconfig.SeaweedConfigKey: compiled.Config})
	if err != nil {
		return err
	}
	defer clearData(data)
	if !bytes.Equal(data[providerconfig.SeaweedConfigKey], compiled.Config) {
		// A new principal set (chart upgrade) replaces the compiled document.
		_, err = s.patch(ctx, name, map[string][]byte{providerconfig.SeaweedConfigKey: compiled.Config})
	}
	return err
}

func runSecrets(ctx context.Context, p contracts.SecretsPlan, config *rest.Config, kubeAPI contracts.OwnerProviderEndpoint) error {
	if ctx == nil || ctx.Err() != nil || config == nil || !validSecretsPlan(p) {
		return mounts.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	typedConfig := rest.CopyConfig(config)
	typedConfig.ContentType = "application/json"
	// About three requests per Secret; the client-go default of 5 QPS would
	// stretch a run to tens of seconds.
	typedConfig.QPS, typedConfig.Burst = 50, 100
	client, err := kubernetes.NewForConfig(typedConfig)
	if err != nil {
		return mounts.ErrUnavailable
	}
	store := secretStore{api: client.CoreV1().Secrets(p.Namespace), namespace: p.Namespace}
	pg := contracts.SmallPostgresPlan{Format: contracts.SmallPostgresFormat, Namespace: p.Namespace, Name: p.Name, Keycloak: p.Keycloak != nil && !p.KeycloakExternalDatabase}
	var prepareKC, preparePG, prepareS3, prepareKeys func(context.Context) error
	if p.Keycloak != nil {
		if !p.KeycloakExternalDatabase && (!p.Postgres || p.Keycloak.Database != (contracts.SmallKeycloakDatabase{Host: pg.Host(), Port: 5432, Database: "keycloak", Username: "keycloak"})) {
			return mounts.ErrUnavailable
		}
		databaseState := pg.StateSecretName()
		if p.KeycloakExternalDatabase {
			databaseState = ""
		}
		state, e := kube.NewSmallKeycloakStateStore(config, *p.Keycloak, databaseState)
		if e != nil {
			return mounts.ErrUnavailable
		}
		service, e := NewSmallKeycloakPreparation(state, *p.Keycloak)
		if e != nil {
			return mounts.ErrUnavailable
		}
		prepareKC = func(ctx context.Context) error {
			if _, err := service.Prepare(ctx); err != nil {
				return secretsFailure("KeycloakStateUnavailable")
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
				return secretsFailure("PostgresStateUnavailable")
			}
			return nil
		}
	}
	var admin contracts.SeaweedCredential
	defer func() { admin.SecretAccessKey = "" }()
	if p.ObjectStore != nil {
		service, e := kube.NewSmallSeaweedPreparation(config, *p.ObjectStore)
		if e != nil {
			return mounts.ErrUnavailable
		}
		prepareS3 = func(ctx context.Context) error {
			state, err := service.Prepare(ctx)
			if err != nil {
				return secretsFailure("ObjectStoreStateUnavailable")
			}
			admin = state.Admin
			return nil
		}
	}
	if p.OpenBao != nil {
		plan := contracts.SmallOpenBaoPlan{Format: contracts.SmallOpenBaoFormat, Namespace: p.Namespace, Name: p.Name, Image: p.OpenBao.Image, Kubernetes: kubeAPI, SetupAccount: p.Name + "-setup"}
		service, err := kube.NewSmallOpenBaoPreparation(config, plan)
		if err != nil {
			return mounts.ErrUnavailable
		}
		prepareKeys = func(ctx context.Context) error {
			state, err := service.Prepare(ctx)
			clear(state.RootsPEM)
			if err != nil {
				return secretsFailure("KeyServiceStateUnavailable")
			}
			return nil
		}
	}
	if err := prepareSmallServices(ctx, prepareKC, preparePG, prepareS3, prepareKeys); err != nil {
		return err
	}
	ids, err := store.ids(ctx, p.IDs)
	if err != nil {
		return err
	}
	installation := ids["installationID"]
	for _, entry := range p.SQL {
		if err := store.sql(ctx, installation, entry); err != nil {
			return err
		}
	}
	if p.AuditMAC != "" {
		if err := store.auditMAC(ctx, p.AuditMAC); err != nil {
			return err
		}
	}
	if p.ArtifactKey != "" {
		if err := store.artifactKey(ctx, p.ArtifactKey, installation); err != nil {
			return err
		}
	}
	if p.ObjectStore != nil {
		if err := store.objectStore(ctx, p, ids, admin); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// RunSecrets runs in the pre-install/pre-upgrade `secrets` hook Job.
func RunSecrets(ctx context.Context) error {
	if disableWorkerCoreDumps() != nil {
		return mounts.ErrUnavailable
	}
	files, err := os.OpenRoot(SecretsRoot)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer files.Close()
	raw, err := mounts.Read(ctx, files, "secrets.json", contracts.SecretsMaxBytes)
	if err != nil {
		return mounts.ErrUnavailable
	}
	p, err := contracts.DecodeSecretsPlan(bytes.NewReader(raw))
	if err != nil {
		return secretsFailure("InvalidPlan")
	}
	config, err := rest.InClusterConfig()
	if err != nil {
		return mounts.ErrUnavailable
	}
	ca, err := os.ReadFile(serviceAccountCA)
	if err != nil {
		return mounts.ErrUnavailable
	}
	roots, err := providerconfig.TrustRootsPEM(ca, time.Now())
	if err != nil {
		return mounts.ErrUnavailable
	}
	return runSecrets(ctx, p, config, contracts.OwnerProviderEndpoint{Endpoint: secretsKubernetesEndpoint, Roots: roots})
}
