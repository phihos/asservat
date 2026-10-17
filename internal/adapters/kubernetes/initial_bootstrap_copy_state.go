package kubernetes

import (
	cfg "asservat.local/asservat/internal/domain/configuration"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func bootstrapCopyClaimValid(d contracts.InitialBootstrap, c contracts.InitialBootstrapCopyClaim) bool {
	if !contracts.InitialBootstrapHasCopyClosure(d.Format) || c.Format != contracts.InitialBootstrapCopyClaimFormat || !initialHandoverTime(c.StartedAt) || !initialHandoverTime(c.Until) || c.Until.Sub(c.StartedAt) != contracts.InitialBootstrapCopyCleanupDuration || !initialHandoverTime(c.ManagerRetiredAt) || c.ManagerRetiredAt.After(c.StartedAt) {
		return false
	}
	n := bootstrapNames(d)
	refs := []contracts.WorkerObjectReference{c.Namespace, c.Seed, c.Projection, c.History, c.Root, c.SQL, c.Provider}
	names := []string{d.BootstrapNamespace, n.seed, n.projection, n.passiveHistory, n.root, n.sqlMaterial, n.providerMaterial}
	seen := map[string]bool{}
	for i, r := range refs {
		if r.Name != names[i] || !authorization.UUID(r.UID) || seen[r.UID] {
			return false
		}
		seen[r.UID] = true
	}
	for _, id := range []string{c.OperationID, c.InstallationID, c.RequestID, c.ManagerCloseID, c.ActivatedClaimID, c.PolicyOperationID, c.BindingOperationID} {
		if !authorization.UUID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func bootstrapCopyReceiptValid(c contracts.InitialBootstrapCopyClaim, r contracts.InitialBootstrapCopyReceipt, uid string) bool {
	return authorization.UUID(r.UID) && (uid == "" || r.UID == uid) && identity.Text(r.ResourceVersion, 128) && initialHandoverTime(r.ObservedAt) && !r.ObservedAt.Before(c.StartedAt) && r.ObservedAt.Before(c.Until)
}

// InitialBootstrapCopyState is an internal observation of fixed public seed
// metadata. No field is a transferable permit or a caller-selected effect.
type InitialBootstrapCopyState struct {
	Claim                             contracts.InitialBootstrapCopyClaim
	PolicyStartedAt, BindingStartedAt *time.Time
	Policy, Binding                   *contracts.InitialBootstrapCopyReceipt
	SQLMarked, ProviderMarked         *contracts.InitialBootstrapCopyReceipt
	SQLRemoved, ProviderRemoved       *contracts.InitialBootstrapCopyReceipt
	CompletedAt                       *time.Time
	ValidUntil                        time.Time
}

func (s InitialBootstrapCopyState) complete() bool {
	return s.CompletedAt != nil && s.Policy != nil && s.Binding != nil && s.SQLRemoved != nil && s.ProviderRemoved != nil
}

func bootstrapManagerRetirementValid(v contracts.InitialBootstrapManagerRetirement) bool {
	return authorization.UUID(v.OperationID) && identity.Text(v.Manager.Name, 63) && v.Manager.OID != 0 && v.Manager.OID != 10 && initialHandoverTime(v.StartedAt) && initialHandoverTime(v.Until) && v.Until.Sub(v.StartedAt) == 30*time.Second && initialHandoverTime(v.RetiredAt) && !v.RetiredAt.Before(v.StartedAt) && v.RetiredAt.Before(v.Until) && !v.RetiredAt.After(time.Now())
}

func bootstrapReadCopyState(d contracts.InitialBootstrap, m *meta.PartialObjectMetadata, p *InitialBootstrapPassiveRead) (*InitialBootstrapCopyState, error) {
	raw, exists := m.Annotations[bootstrapCopyClaimAnnotation]
	if !exists {
		for _, k := range bootstrapCopyAnnotations() {
			if _, ok := m.Annotations[k]; ok {
				return nil, cfg.ErrChanged
			}
		}
		return nil, nil
	}
	if p == nil || p.ManagerRetirement == nil {
		return nil, cfg.ErrChanged
	}
	c, err := contracts.DecodeInitialBootstrapCopyClaim(strings.NewReader(raw))
	b := p.Bundle
	v := b.Configuration
	if err != nil || !bootstrapCopyClaimValid(d, c) || c.StartedAt.After(time.Now()) || c.Namespace != b.Observation.Prelude.Namespace || c.Seed != b.Seed || c.Projection != b.Observation.Projection || c.History.Name != bootstrapNames(d).passiveHistory || c.InstallationID != v.Plan.InstallationID || c.RequestID != v.Plan.RequestID || c.Root.Name != v.Plan.RootName || c.ManagerCloseID != p.ManagerRetirement.OperationID || !c.ManagerRetiredAt.Equal(p.ManagerRetirement.RetiredAt) || v.SQLMaterial == nil || c.SQL != *v.SQLMaterial || v.Providers == nil || c.Provider != v.Providers.Material {
		return nil, cfg.ErrChanged
	}
	locator, err := contracts.DecodeInitialBootstrapPassiveLocator(strings.NewReader(m.Annotations[initialBootstrapPassiveAnnotation]))
	if err != nil || c.History != locator.History {
		return nil, cfg.ErrChanged
	}
	state := &InitialBootstrapCopyState{Claim: c, ValidUntil: p.ValidUntil}
	for _, item := range []struct {
		key string
		out **time.Time
	}{
		{bootstrapCopyPolicyStartedAnnotation, &state.PolicyStartedAt}, {bootstrapCopyBindingStartedAnnotation, &state.BindingStartedAt}, {bootstrapCopyCompleteAnnotation, &state.CompletedAt},
	} {
		if raw, ok := m.Annotations[item.key]; ok {
			at, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil || !initialHandoverTime(at) || at.Before(c.StartedAt) || !at.Before(c.Until) || at.After(time.Now()) || raw != at.UTC().Format(time.RFC3339Nano) {
				return nil, cfg.ErrChanged
			}
			*item.out = &at
		}
	}
	for _, item := range []struct {
		key, uid string
		out      **contracts.InitialBootstrapCopyReceipt
	}{
		{bootstrapCopyPolicyAnnotation, "", &state.Policy}, {bootstrapCopyBindingAnnotation, "", &state.Binding},
		{bootstrapCopySQLMarkedAnnotation, c.SQL.UID, &state.SQLMarked}, {bootstrapCopyProviderMarkedAnnotation, c.Provider.UID, &state.ProviderMarked},
		{bootstrapCopySQLAnnotation, c.SQL.UID, &state.SQLRemoved}, {bootstrapCopyProviderAnnotation, c.Provider.UID, &state.ProviderRemoved},
	} {
		if raw, ok := m.Annotations[item.key]; ok {
			r, err := contracts.DecodeInitialBootstrapCopyReceipt(strings.NewReader(raw))
			if err != nil || !bootstrapCopyReceiptValid(c, r, item.uid) || r.ObservedAt.After(time.Now()) {
				return nil, cfg.ErrChanged
			}
			*item.out = &r
		}
	}
	if state.Policy != nil && (state.PolicyStartedAt == nil || state.Policy.ObservedAt.Before(*state.PolicyStartedAt)) || state.BindingStartedAt != nil && (state.Policy == nil || state.BindingStartedAt.Before(state.Policy.ObservedAt)) || state.Binding != nil && (state.BindingStartedAt == nil || state.Binding.ObservedAt.Before(*state.BindingStartedAt) || state.Policy.UID == state.Binding.UID) {
		return nil, cfg.ErrChanged
	}
	for _, pair := range []struct {
		marked, removed *contracts.InitialBootstrapCopyReceipt
	}{{state.SQLMarked, state.SQLRemoved}, {state.ProviderMarked, state.ProviderRemoved}} {
		if pair.marked != nil && (state.Binding == nil || pair.marked.ObservedAt.Before(state.Binding.ObservedAt)) {
			return nil, cfg.ErrChanged
		}
		if pair.removed != nil && (pair.marked == nil || pair.removed.UID != pair.marked.UID || pair.removed.ResourceVersion != pair.marked.ResourceVersion || pair.removed.ObservedAt.Before(pair.marked.ObservedAt)) {
			return nil, cfg.ErrChanged
		}
	}
	if state.CompletedAt != nil && (!state.complete() || state.CompletedAt.Before(state.SQLRemoved.ObservedAt) || state.CompletedAt.Before(state.ProviderRemoved.ObservedAt)) {
		return nil, cfg.ErrChanged
	}
	return state, nil
}
