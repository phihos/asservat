package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// InitialPreparationCredentialBinder accepts exactly one public interval before
// any SQL role or target Secret effect. It has no provider/effect writer. The
// caller must retain the returned original lease through subsequent work.
type InitialPreparationCredentialBinder struct {
	preparer *InitialPreparer
	material *InitialSQLMaterialReader
	current  *InitialCredentialStateStore
	config   contracts.InitialInstaller
	plan     artifact.Digest
}

func NewInitialPreparationCredentialBinder(p *InitialPreparer, targetAdministrator, targetProbe *PermissionClient, c contracts.InitialInstaller, inputUID string, material contracts.WorkerObjectReference) (*InitialPreparationCredentialBinder, error) {
	expectedFormat := contracts.InitialInstallerFormat
	if p != nil && p.services != nil {
		expectedFormat = contracts.InitialInstallerFormatForServices(p.services.Format)
	}
	if !p.ActivationPreparationEnabled() || targetAdministrator == nil || targetProbe == nil || expectedFormat == "" || c.Format != expectedFormat || c.InstallationID != p.plan.InstallationID || c.ClusterID != p.plan.ClusterID || !authorization.UUID(c.IssuerEpoch) || !authorization.UUID(inputUID) || c.Namespace.Name != p.plan.Workload.Namespace || c.Pod.Name != p.plan.Workload.Name || c.Configuration != p.plan.Workload.Configuration || c.WriterAccount.Name != p.plan.Workload.WriterAccount || c.ProbeAccount.Name != p.plan.Workload.ProbeAccount || c.Witness.Name != p.plan.Workload.Witness || c.FleetSource.Name != p.plan.Workload.FleetSource || c.WorkloadGuard.Name != p.plan.Workload.WorkloadGuard || c.FleetGuard.Name != p.plan.Workload.FleetGuard || c.WitnessGuard.Name != p.plan.Workload.WitnessGuard || !equalJSON(c.WorkloadGuard.Administrators, p.plan.Administrators) || !equalJSON(c.FleetGuard.Administrators, p.plan.Administrators) {
		return nil, cfg.ErrInvalid
	}
	ns := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	workload := cfg.InitialWorkloadAdministration{Handover: c.Handover == contracts.InitialPreparationHandoverProtocol, Name: c.WorkloadGuard.Name, Configuration: c.Configuration, Witness: c.Witness.Name, FleetSource: c.FleetSource.Name, ControlNamespace: ns, PodName: c.Pod.Name, PodUID: c.Pod.UID, WriterAccount: c.WriterAccount.Name, WriterAccountUID: c.WriterAccount.UID, ProbeAccount: c.ProbeAccount.Name, ProbeAccountUID: c.ProbeAccount.UID}
	for _, a := range c.WorkloadGuard.Administrators {
		workload.Administrators = append(workload.Administrators, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
	}
	digest, e := hex.DecodeString(c.PodSpecDigest)
	if e != nil || len(digest) != 32 || hex.EncodeToString(digest) != c.PodSpecDigest {
		return nil, cfg.ErrInvalid
	}
	copy(workload.PodSpecDigest[:], digest)
	encoded, e := json.Marshal(c)
	if e != nil {
		return nil, cfg.ErrInvalid
	}
	plan := artifact.Digest(sha256.Sum256(encoded))
	guard := GuardPin{PolicyUID: c.WorkloadGuard.PolicyUID, PolicyGeneration: c.WorkloadGuard.PolicyGeneration, BindingUID: c.WorkloadGuard.BindingUID, BindingResourceVersion: c.WorkloadGuard.BindingResourceVersion}
	if targetAdministrator.api.Get().URL().String() != p.creator.api.Get().URL().String() || targetProbe.api.Get().URL().String() != p.creator.api.Get().URL().String() {
		return nil, cfg.ErrInvalid
	}
	protection, e := NewInitialWorkloadProtection(targetAdministrator, targetProbe, workload, guard)
	if e != nil {
		return nil, e
	}
	private, e := NewInitialSQLMaterialReader(p, material)
	if e != nil {
		return nil, e
	}
	return &InitialPreparationCredentialBinder{preparer: p, material: private, current: &InitialCredentialStateStore{protection: protection, inputUID: inputUID, installation: c.InstallationID, plan: plan}, config: c, plan: plan}, nil
}

func (b *InitialPreparationCredentialBinder) Bind(ctx context.Context) (contracts.InitialSQLMaterial, contracts.InitialPreparationCredentialBinding, time.Time, error) {
	var zero contracts.InitialSQLMaterial
	var noBinding contracts.InitialPreparationCredentialBinding
	if b == nil || ctx == nil {
		return zero, noBinding, time.Time{}, cfg.ErrInvalid
	}
	s := b.preparer
	until, e := s.current(ctx)
	if e != nil {
		return zero, noBinding, time.Time{}, e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	material, materialUntil, e := b.material.ReadInitialSQLMaterial(ctx)
	until = identity.Earlier(until, materialUntil)
	if e != nil {
		return zero, noBinding, time.Time{}, e
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	finalUntil, e := b.current.current(ctx, true)
	until = identity.Earlier(until, finalUntil)
	if e != nil {
		return zero, noBinding, time.Time{}, e
	}
	cm, w, e := s.read(ctx)
	if e != nil || w.Phase != "declared" || w.Activation == nil || w.Activation.Pod == nil || w.Activation.Pod.Receipt == nil || w.Activation.Pod.Receipt.UID != b.config.Pod.UID || w.Activation.Pod.SpecDigest != b.config.PodSpecDigest {
		return zero, noBinding, time.Time{}, cfg.ErrChanged
	}
	// Root receipts bind the actual namespace and accounts, never names alone.
	for _, ref := range []struct {
		kind  string
		value contracts.WorkerObjectReference
	}{{"Namespace", b.config.Namespace}, {"ServiceAccount", b.config.WriterAccount}, {"ServiceAccount", b.config.ProbeAccount}} {
		matched := false
		for _, entry := range w.Creates {
			if entry.Kind == ref.kind && entry.Name == ref.value.Name && entry.Receipt != nil && entry.Receipt.UID == ref.value.UID {
				matched = true
			}
		}
		if !matched {
			return zero, noBinding, time.Time{}, cfg.ErrChanged
		}
	}
	digest := hex.EncodeToString(b.plan[:])
	if c := w.Activation.Credentials; c != nil {
		if c.Material != b.material.ref || c.StartupDigest != digest {
			return zero, noBinding, time.Time{}, cfg.ErrChanged
		}
	} else {
		n := s.protection.observer.now().UTC().Truncate(time.Second)
		w.Activation.Credentials = &contracts.InitialPreparationCredentialBinding{Material: b.material.ref, StartupDigest: digest, NotBefore: n, NotAfter: n.Add(15 * time.Minute)}
		if e = s.write(ctx, cm, w, until); e != nil {
			return zero, noBinding, time.Time{}, e
		}
	}
	finalUntil, e = b.current.current(ctx, true)
	until = identity.Earlier(until, finalUntil)
	if e != nil || ctx.Err() != nil || !s.protection.observer.now().Before(until) {
		return zero, noBinding, time.Time{}, cfg.ErrUnavailable
	}
	if e = s.finish(ctx, until); e != nil {
		return zero, noBinding, time.Time{}, e
	}
	// Expiry is retained for exact retirement. This return grants no permission
	// to provision; InitialSQLRoles enforces the same original credential dates.
	return material, *w.Activation.Credentials, until, nil
}
