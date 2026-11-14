package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"slices"
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

// auditMAC creates the operation/account MAC keys once. Their versions use
// the roleSetupID: `<id>-input/v1` and `<id>-account/v1`, the capacity
// account version the hub-worker derives. The Secret holds the four raw keys
// (hub-worker, federation) and their public-audit-keys.json projection
// (hub-api), always derived from the stored keys.
func (s secretStore) auditMAC(ctx context.Context, name string, ids installationIDs) error {
	input, err := randomKey()
	account, err2 := randomKey()
	defer clear(input)
	defer clear(account)
	if err != nil || err2 != nil {
		return secretsFailure("RandomUnavailable")
	}
	setup := ids["roleSetupID"]
	projection := func(input, account []byte) []byte {
		b, _ := json.Marshal(contracts.PublicAuditKeys{Format: contracts.PublicAuditKeysFormat, InstallationID: ids["installationID"], RootUID: ids["permissionRootID"], SetupID: setup,
			Material: contracts.PublicAuditKeyMaterial{InputVersion: setup + "-input/v1", AccountVersion: setup + "-account/v1", InputKey: input, AccountKey: account}})
		return b
	}
	want := map[string][]byte{contracts.AuditMACInputVersion: []byte(setup + "-input/v1"), contracts.AuditMACInputKey: input, contracts.AuditMACAccountVersion: []byte(setup + "-account/v1"), contracts.AuditMACAccountKey: account, contracts.PublicAuditKeysFile: projection(input, account)}
	defer clear(want[contracts.PublicAuditKeysFile])
	data, err := s.ensure(ctx, name, want)
	if err != nil {
		return err
	}
	defer clearData(data)
	if len(data[contracts.AuditMACInputKey]) != 32 || len(data[contracts.AuditMACAccountKey]) != 32 || string(data[contracts.AuditMACInputVersion]) != setup+"-input/v1" || string(data[contracts.AuditMACAccountVersion]) != setup+"-account/v1" {
		return secretsFailure("InvalidAuditMAC " + name)
	}
	stored := projection(data[contracts.AuditMACInputKey], data[contracts.AuditMACAccountKey])
	defer clear(stored)
	if !bytes.Equal(data[contracts.PublicAuditKeysFile], stored) {
		// The projection was added to older raw keys: derive it from them.
		patched, err := s.patch(ctx, name, map[string][]byte{contracts.PublicAuditKeysFile: stored})
		clearData(patched)
		return err
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

// SeaweedBucketPoliciesKey is the IAM Secret key holding the compiled bucket
// policies (bucket name -> policy) that `asservat setup` applies.
const SeaweedBucketPoliciesKey = "bucket-policies.json"

// seaweedEvidencePurposes use the evidence bucket; every other principal
// uses the audit bucket. Regional history shares the evidence bucket.
var seaweedEvidencePurposes = []string{"publisher-read", "download-read", "evidence-delete", "regional-write", "regional-history"}

// objectStore creates one credential Secret per bundled SeaweedFS principal
// and compiles the complete IAM configuration and bucket policies from them.
func (s secretStore) objectStore(ctx context.Context, p contracts.SecretsPlan, ids installationIDs, admin contracts.SeaweedCredential) error {
	installation, cluster, root := ids["installationID"], ids["clusterID"], ids["permissionRootID"]
	var grants []contracts.SeaweedGrant
	defer func() {
		for i := range grants {
			grants[i].Credential.SecretAccessKey = ""
		}
	}()
	type principal struct{ purpose, scope, secret string }
	var principals []principal
	for _, purpose := range contracts.ObjectStorePrincipals(p.Mode) {
		scope := installation
		if strings.HasPrefix(purpose, "regional-") {
			scope = cluster
		}
		principals = append(principals, principal{purpose, scope, p.Name + "-s3-" + purpose})
	}
	// ADR-331: each joined cluster's regional capabilities, scoped to it.
	for _, r := range p.RemoteClusters {
		if !authorization.UUID(r.ClusterID) || r.ClusterID == cluster {
			return secretsFailure("InvalidRemoteCluster " + r.Name)
		}
		for _, purpose := range contracts.RemoteObjectStorePrincipals() {
			principals = append(principals, principal{purpose, r.ClusterID, contracts.RemoteObjectStoreSecret(p.Name, purpose, r.Name)})
		}
	}
	for _, x := range principals {
		purpose, scope := x.purpose, x.scope
		key := contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: scope}
		generated, err := providerconfig.GenerateSeaweedCredential(key)
		if err != nil {
			return secretsFailure("ObjectStoreCredentialUnavailable " + purpose)
		}
		want, _ := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: generated.AccessKeyID, SecretAccessKey: generated.SecretAccessKey})
		name := x.secret
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
		bucket := p.Name + "-audit"
		if slices.Contains(seaweedEvidencePurposes, purpose) {
			bucket = p.Name + "-evidence"
		}
		grant := contracts.SeaweedGrant{Credential: credential, Bucket: bucket, InstallationID: installation, ClusterID: cluster, RootID: root}
		if strings.HasPrefix(purpose, "regional-") {
			grant.ClusterID = scope
		}
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
	policies, err := json.Marshal(compiled.Policies)
	if err != nil {
		return secretsFailure("ObjectStoreIAMUnavailable")
	}
	want := map[string][]byte{providerconfig.SeaweedConfigKey: compiled.Config, SeaweedBucketPoliciesKey: policies}
	name := p.ObjectStore.IAMSecretName()
	data, err := s.ensure(ctx, name, want)
	if err != nil {
		return err
	}
	defer clearData(data)
	changed := map[string][]byte{}
	for k, v := range want {
		if !bytes.Equal(data[k], v) {
			changed[k] = v
		}
	}
	if len(changed) > 0 {
		// A new principal set (chart upgrade) replaces the compiled documents.
		patched, err := s.patch(ctx, name, changed)
		clearData(patched)
		return err
	}
	return nil
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
		if err := store.auditMAC(ctx, p.AuditMAC, ids); err != nil {
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
	for _, entry := range p.ServingTLS {
		if err := store.servingTLS(ctx, entry); err != nil {
			return err
		}
	}
	if c := p.DownloadStore; c != nil {
		if err := store.copyImmutable(ctx, client.CoreV1().Secrets(c.Namespace), *c); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// copyImmutable creates an immutable copy of one credential.json Secret in
// another namespace once; an existing copy is kept.
func (s secretStore) copyImmutable(ctx context.Context, target typed.SecretInterface, c contracts.SecretsCopy) error {
	if _, err := target.Get(ctx, c.Secret, meta.GetOptions{}); err == nil {
		return nil
	} else if !apierrors.IsNotFound(err) {
		return secretsFailure("SecretUnavailable " + c.Namespace + "/" + c.Secret)
	}
	source, err := s.api.Get(ctx, c.Source, meta.GetOptions{})
	if err != nil || len(source.Data[contracts.ObjectStoreCredentialFile]) == 0 {
		return secretsFailure("SecretUnavailable " + c.Source)
	}
	defer clearData(source.Data)
	// The download worker reads its own closed format (no empty session token).
	stored, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(source.Data[contracts.ObjectStoreCredentialFile]))
	if err != nil || stored.AccessKeyID == "" || stored.SecretAccessKey == "" || stored.SessionToken != "" {
		return secretsFailure("InvalidObjectStoreCredential " + c.Source)
	}
	worker, err := json.Marshal(contracts.WorkerStoreCredentials{AccessKeyID: stored.AccessKeyID, SecretAccessKey: stored.SecretAccessKey})
	if err != nil {
		return secretsFailure("InvalidObjectStoreCredential " + c.Source)
	}
	defer clear(worker)
	immutable := true
	object := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: c.Secret, Namespace: c.Namespace, Labels: map[string]string{"app.kubernetes.io/part-of": "asservat", "app.kubernetes.io/created-by": "asservat-secrets"}}, Type: core.SecretTypeOpaque, Immutable: &immutable,
		Data: map[string][]byte{contracts.ObjectStoreCredentialFile: worker}}
	if _, err = target.Create(ctx, object, meta.CreateOptions{FieldValidation: "Strict"}); err != nil && !apierrors.IsAlreadyExists(err) {
		return secretsFailure("SecretUnavailable " + c.Namespace + "/" + c.Secret)
	}
	return nil
}

// servingTLS creates a peer listener's kubernetes.io/tls Secret once: an own
// ECDSA P-256 CA and a leaf for the Service names. An existing Secret is kept.
func (s secretStore) servingTLS(ctx context.Context, entry contracts.SecretsServingTLS) error {
	if _, err := s.api.Get(ctx, entry.Secret, meta.GetOptions{}); err == nil {
		return nil
	} else if !apierrors.IsNotFound(err) {
		return secretsFailure("SecretUnavailable " + entry.Secret)
	}
	data, err := servingTLSMaterial(entry.Secret, entry.DNSNames, time.Now())
	if err != nil {
		return secretsFailure("ServingTLSUnavailable " + entry.Secret)
	}
	defer clearData(data)
	object := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: entry.Secret, Namespace: s.namespace, Labels: map[string]string{"app.kubernetes.io/part-of": "asservat", "app.kubernetes.io/created-by": "asservat-secrets"}}, Type: core.SecretTypeTLS, Data: data}
	if _, err = s.api.Create(ctx, object, meta.CreateOptions{FieldValidation: "Strict"}); err != nil && !apierrors.IsAlreadyExists(err) {
		return secretsFailure("SecretUnavailable " + entry.Secret)
	}
	return nil
}

func servingTLSMaterial(name string, dns []string, now time.Time) (map[string][]byte, error) {
	if len(dns) == 0 {
		return nil, errors.New("no DNS names")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial := func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127)); return n }
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name + " CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	if ca, err = x509.ParseCertificate(caDER); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: dns[0]}, DNSNames: dns, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		"ca.crt":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		"tls.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
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
