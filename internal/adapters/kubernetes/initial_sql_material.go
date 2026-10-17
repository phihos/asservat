package kubernetes

import (
	"bytes"
	"context"
	"encoding/base64"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// InitialSQLMaterialReader reads one independently pinned immutable bootstrap
// Secret. It cannot create/adopt a Secret, rotate passwords or choose new pins.
// The trusted installation composition owns the original Secret reference.
type InitialSQLMaterialReader struct {
	preparer *InitialPreparer
	ref      contracts.WorkerObjectReference
}

func NewInitialSQLMaterialReader(preparer *InitialPreparer, ref contracts.WorkerObjectReference) (*InitialSQLMaterialReader, error) {
	if preparer == nil || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 || !authorization.UUID(ref.UID) {
		return nil, cfg.ErrInvalid
	}
	return &InitialSQLMaterialReader{preparer: preparer, ref: ref}, nil
}
func initialMaterialValid(m contracts.InitialSQLMaterial, installation, request string) bool {
	if m.Format != contracts.InitialSQLMaterialFormat || m.InstallationID != installation || m.RequestID != request {
		return false
	}
	seen := map[string]bool{}
	for _, password := range []string{m.PreparationPassword, m.AuditPassword, m.ActivationPassword} {
		b, e := base64.RawURLEncoding.DecodeString(password)
		valid := e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == password
		clear(b)
		if !valid || seen[password] {
			return false
		}
		seen[password] = true
	}
	return true
}
func (s *InitialSQLMaterialReader) ReadInitialSQLMaterial(ctx context.Context) (contracts.InitialSQLMaterial, time.Time, error) {
	var zero contracts.InitialSQLMaterial
	if s == nil || s.preparer == nil || ctx == nil {
		return zero, time.Time{}, cfg.ErrInvalid
	}
	p := s.preparer
	until, e := p.current(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	_, root, e := p.read(ctx)
	if e != nil || root.RootUID == "" || root.Phase == "declaring" {
		return zero, time.Time{}, cfg.ErrUnavailable
	}
	m, e := s.readPinnedMaterial(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	if e = p.finish(ctx, until); e != nil {
		return zero, time.Time{}, e
	}
	return m, until, nil
}

// CheckInitialSQLMaterial validates only the protected, unissued input before
// any preparation mutation. It creates/adopts nothing and returns no credential,
// original-root binding, validity interval, or provisioning authority.
func (s *InitialSQLMaterialReader) CheckInitialSQLMaterial(ctx context.Context) error {
	return s.checkInitialSQLMaterial(ctx, "")
}

// CheckInitialSQLHistoryPassword checks the independent fourth bootstrap
// password before preparation starts. It returns no material, root binding or
// provisioning authority; the bound reader remains required for issuance.
func (s *InitialSQLMaterialReader) CheckInitialSQLHistoryPassword(ctx context.Context, password string) error {
	raw, e := base64.RawURLEncoding.DecodeString(password)
	valid := e == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == password
	clear(raw)
	if !valid {
		return cfg.ErrInvalid
	}
	return s.checkInitialSQLMaterial(ctx, password)
}

func (s *InitialSQLMaterialReader) checkInitialSQLMaterial(ctx context.Context, historyPassword string) error {
	if s == nil || s.preparer == nil || ctx == nil {
		return cfg.ErrInvalid
	}
	until, e := s.preparer.current(ctx)
	if e != nil {
		return e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	material, e := s.readPinnedMaterial(ctx)
	if e != nil {
		return e
	}
	if historyPassword != "" && (historyPassword == material.PreparationPassword || historyPassword == material.AuditPassword || historyPassword == material.ActivationPassword) {
		return cfg.ErrChanged
	}
	return s.preparer.finish(ctx, until)
}
func (s *InitialSQLMaterialReader) readPinnedMaterial(ctx context.Context) (contracts.InitialSQLMaterial, error) {
	var zero contracts.InitialSQLMaterial
	p := s.preparer
	raw, e := p.creator.raw(ctx, "/api/v1/namespaces/"+p.plan.BootstrapNamespace.Name+"/secrets/"+s.ref.Name, nil)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	defer clear(raw)
	var secret core.Secret
	if strictGuardJSON(raw, &secret) != nil {
		return zero, cfg.ErrChanged
	}
	for _, b := range secret.Data {
		defer clear(b)
	}
	if secret.APIVersion != "v1" || secret.Kind != "Secret" || secret.Type != core.SecretTypeOpaque || !ownerMetadata(secret.ObjectMeta, p.plan.BootstrapNamespace.Name, s.ref.Name, s.ref.UID) || secret.Immutable == nil || !*secret.Immutable || len(secret.OwnerReferences) != 0 || len(secret.Data) != 1 || len(secret.StringData) != 0 {
		return zero, cfg.ErrChanged
	}
	m, e := contracts.DecodeInitialSQLMaterial(bytes.NewReader(secret.Data["material.json"]))
	if e != nil || !initialMaterialValid(m, p.plan.InstallationID, p.plan.RequestID) {
		return zero, cfg.ErrChanged
	}
	return m, nil
}
