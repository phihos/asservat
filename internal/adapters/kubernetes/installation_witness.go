package kubernetes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	authentication "k8s.io/api/authentication/v1"
	kubeauth "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const installationWitnessDenial = "Asservat installation bootstrap administrator is required."

// This helper supplies fresh data to the installer, never create-if-missing
// behavior to a runtime consumer. Installation pins the returned object's UID.
func FreshInstallationWitnessData(installation, epoch, writerUID string) (map[string]string, error) {
	if !authorization.UUID(installation) || !authorization.UUID(epoch) || !authorization.UUID(writerUID) {
		return nil, value.ErrInvalid
	}
	b, err := json.Marshal(contracts.InstallationWitness{SchemaVersion: "installation-witness/v1", InstallationID: installation, IssuerEpoch: epoch, WriterAccountUID: writerUID})
	return map[string]string{"witness.json": string(b)}, err
}

func InstallationWitnessAdmission(p cfg.ConfigMapAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	return configMapAdmission(p, "protected-installation-witness", installationWitnessDenial)
}

type InstallationWitnessReader struct {
	protection *configMapProtection
	scope      value.InstallationWitnessScope
}

type InstallationWitnessConsumer struct {
	reader *InstallationWitnessReader
	writer *PermissionClient
}

var _ app.InstallationWitnessReader = (*InstallationWitnessReader)(nil)
var _ app.InstallationWitnessConsumer = (*InstallationWitnessConsumer)(nil)

func NewInstallationWitnessReader(observer, probe *PermissionClient, p cfg.ConfigMapAdministration, pin GuardPin, scope value.InstallationWitnessScope) (*InstallationWitnessReader, error) {
	if !scope.Valid() || observer == nil || observer.clusterID != scope.ClusterID || p.ControlNamespace != (cfg.NamespaceRef{Name: scope.Namespace, UID: scope.NamespaceUID}) || p.SourceName != scope.Name || len(validation.IsDNS1123Label(scope.WriterAccount)) != 0 {
		return nil, value.ErrInvalid
	}
	writerAllowed := false
	for _, a := range p.Administrators {
		writerAllowed = writerAllowed || a == (cfg.KubernetesActor{Kind: "User", Name: scope.WriterUsername()})
	}
	if !writerAllowed {
		return nil, value.ErrInvalid
	}
	g, err := newConfigMapProtection(observer, probe, p, pin, "protected-installation-witness", installationWitnessDenial)
	if err != nil {
		return nil, err
	}
	return &InstallationWitnessReader{g, scope}, nil
}

func NewInstallationWitnessConsumer(reader *InstallationWitnessReader, writer *PermissionClient) (*InstallationWitnessConsumer, error) {
	if reader == nil || reader.protection == nil || writer == nil || writer == reader.protection.probe || writer.clusterID != reader.scope.ClusterID || writer.control != reader.protection.plan.ControlNamespace {
		return nil, value.ErrInvalid
	}
	return &InstallationWitnessConsumer{reader, writer}, nil
}

func witnessClaimWire(c value.InitialActivationClaim) *contracts.InitialActivationClaim {
	return &contracts.InitialActivationClaim{ID: c.ID, DatabaseStart: c.Database.StartedAt.UTC().Format(time.RFC3339Nano), DatabaseOID: c.Database.DatabaseOID, SchemaVersion: c.Database.SchemaVersion, SourceUID: c.FleetSource.UID, SourceVersion: c.FleetSource.Generation, SourceDigest: hex.EncodeToString(c.FleetSource.Digest[:]), PlanDigest: hex.EncodeToString(c.PlanDigest[:]), NotBefore: c.NotBefore.UTC().Format(time.RFC3339Nano), NotAfter: c.NotAfter.UTC().Format(time.RFC3339Nano)}
}

func witnessClaimValue(c *contracts.InitialActivationClaim) (*value.InitialActivationClaim, error) {
	if c == nil {
		return nil, nil
	}
	out := &value.InitialActivationClaim{ID: c.ID, Database: value.DatabaseIncarnation{DatabaseOID: c.DatabaseOID, SchemaVersion: c.SchemaVersion}, FleetSource: identity.Revision{UID: c.SourceUID, Generation: c.SourceVersion}}
	for _, field := range []struct {
		text string
		dst  []byte
	}{{c.SourceDigest, out.FleetSource.Digest[:]}, {c.PlanDigest, out.PlanDigest[:]}} {
		b, err := hex.DecodeString(field.text)
		if err != nil || len(b) != 32 {
			return nil, value.ErrInvalid
		}
		copy(field.dst, b)
	}
	for _, field := range []struct {
		text string
		dst  *time.Time
	}{{c.DatabaseStart, &out.Database.StartedAt}, {c.NotBefore, &out.NotBefore}, {c.NotAfter, &out.NotAfter}} {
		t, err := time.Parse(time.RFC3339Nano, field.text)
		if err != nil || t.UTC().Format(time.RFC3339Nano) != field.text {
			return nil, value.ErrInvalid
		}
		*field.dst = t.UTC()
	}
	if !out.Valid() {
		return nil, value.ErrInvalid
	}
	return out, nil
}

func (r *InstallationWitnessReader) path() string {
	return "/api/v1/namespaces/" + r.scope.Namespace + "/configmaps/" + r.scope.Name
}

func (r *InstallationWitnessReader) read(ctx context.Context) (*core.ConfigMap, contracts.InstallationWitness, *value.InitialActivationClaim, error) {
	var wire contracts.InstallationWitness
	raw, err := r.protection.observer.raw(ctx, r.path(), nil)
	if err != nil || permissionJSON(raw, 32<<10, 4096) != nil {
		return nil, wire, nil, value.ErrUnavailable
	}
	var cm core.ConfigMap
	if json.Unmarshal(raw, &cm) != nil || cm.APIVersion != "v1" || cm.Kind != "ConfigMap" || cm.Name != r.scope.Name || cm.Namespace != r.scope.Namespace || string(cm.UID) != r.scope.UID || !identity.Text(cm.ResourceVersion, 128) || cm.DeletionTimestamp != nil || len(cm.OwnerReferences) != 0 || len(cm.BinaryData) != 0 || len(cm.Data) != 1 || len(cm.Data["witness.json"]) > 8<<10 {
		return nil, wire, nil, value.ErrDenied
	}
	if _, err = decodePermissionSpec([]byte(cm.Data["witness.json"]), r.protection.observer.validator.witnessSchema, &wire); err != nil || wire.InstallationID != r.scope.InstallationID || wire.IssuerEpoch != r.scope.IssuerEpoch || wire.WriterAccountUID != r.scope.WriterAccountUID {
		return nil, wire, nil, value.ErrDenied
	}
	claim, err := witnessClaimValue(wire.Claim)
	immutable := cm.Immutable != nil && *cm.Immutable
	if err != nil || immutable != (claim != nil) {
		return nil, wire, nil, value.ErrDenied
	}
	return &cm, wire, claim, nil
}

func (r *InstallationWitnessReader) finish(ctx context.Context, start, until time.Time, cm *core.ConfigMap, claim *value.InitialActivationClaim) (value.InstallationWitness, error) {
	g := r.protection
	if _, err := checkAdmissionGuard(ctx, g.observer, g.plan.Name, g.pin, g.policy, g.binding); err != nil {
		return value.InstallationWitness{}, err
	}
	ns, err := g.observer.namespace(ctx, g.plan.ControlNamespace)
	if err != nil || ns.Deleting {
		return value.InstallationWitness{}, value.ErrUnavailable
	}
	w := value.InstallationWitness{Scope: r.scope, Claim: claim, ResourceVersion: cm.ResourceVersion, ObservedAt: start, FreshUntil: identity.Earlier(start.Add(5*time.Second), until)}
	if ctx.Err() != nil || !w.Valid(g.observer.now()) {
		return value.InstallationWitness{}, value.ErrUnavailable
	}
	return w, nil
}

func (r *InstallationWitnessReader) ReadInstallationWitness(ctx context.Context) (value.InstallationWitness, error) {
	var zero value.InstallationWitness
	if r == nil || r.protection == nil || ctx == nil {
		return zero, value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start := r.protection.observer.now()
	_, until, err := r.protection.current(ctx)
	if err != nil {
		return zero, err
	}
	cm, _, claim, err := r.read(ctx)
	if err != nil {
		return zero, err
	}
	return r.finish(ctx, start, until, cm, claim)
}

func (c *InstallationWitnessConsumer) writerCurrent(ctx context.Context) error {
	raw, err := c.writer.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", authentication.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	var who authentication.SelfSubjectReview
	if err != nil || strictGuardJSON(raw, &who) != nil || who.Status.UserInfo.Username != c.reader.scope.WriterUsername() || who.Status.UserInfo.UID != c.reader.scope.WriterAccountUID {
		return value.ErrDenied
	}
	raw, err = c.writer.proofPost(ctx, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", kubeauth.SelfSubjectAccessReview{TypeMeta: meta.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Spec: kubeauth.SelfSubjectAccessReviewSpec{ResourceAttributes: &kubeauth.ResourceAttributes{Namespace: c.reader.scope.Namespace, Verb: "update", Group: "", Version: "v1", Resource: "configmaps", Name: c.reader.scope.Name}}}, nil)
	var access kubeauth.SelfSubjectAccessReview
	if err != nil || strictGuardJSON(raw, &access) != nil || !access.Status.Allowed || access.Status.Denied || access.Status.EvaluationError != "" {
		return value.ErrDenied
	}
	return nil
}

func (c *InstallationWitnessConsumer) ConsumeInstallationWitness(ctx context.Context, claim value.InitialActivationClaim) (value.InstallationWitness, error) {
	var zero value.InstallationWitness
	if c == nil || c.reader == nil || c.reader.protection == nil || c.writer == nil || ctx == nil || !claim.Current(c.writer.now()) {
		return zero, value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	r, start := c.reader, c.writer.now()
	_, until, err := r.protection.current(ctx)
	if err != nil {
		return zero, err
	}
	if err = c.writerCurrent(ctx); err != nil {
		return zero, err
	}
	cm, wire, stored, err := r.read(ctx)
	if err != nil {
		return zero, err
	}
	expected := witnessClaimWire(claim)
	if stored != nil && *wire.Claim != *expected {
		return zero, value.ErrConflict
	}
	if stored == nil {
		if !claim.Current(c.writer.now()) || ctx.Err() != nil {
			return zero, value.ErrUnavailable
		}
		wire.Claim = expected
		b, e := json.Marshal(wire)
		if e != nil {
			return zero, value.ErrInvalid
		}
		cm.Data = map[string]string{"witness.json": string(b)}
		immutable := true
		cm.Immutable = &immutable
		// UID/RV are the original server values. Never retry or create on an
		// ambiguous PUT; an exact independent read determines consumption.
		_ = c.writer.api.Put().AbsPath(r.path()).Param("fieldValidation", "Strict").Body(cm).MaxRetries(0).Do(ctx).Error()
		cm, wire, stored, err = r.read(ctx)
		if err != nil {
			return zero, err
		}
		if stored == nil || *wire.Claim != *expected {
			return zero, value.ErrConflict
		}
	}
	if !claim.Current(c.writer.now()) {
		return zero, value.ErrUnavailable
	}
	return r.finish(ctx, start, identity.Earlier(until, claim.NotAfter), cm, stored)
}
