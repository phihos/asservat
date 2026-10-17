package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

const bootstrapPartialMetadataAccept = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"

func (s *InitialBootstrap) getPassiveSecret(ctx context.Context) ([]byte, error) {
	raw, err := s.api.Get().AbsPath("/api/v1/namespaces/" + s.desired.BootstrapNamespace + "/secrets/" + bootstrapNames(s.desired).passiveHistory).MaxRetries(0).DoRaw(ctx)
	if err != nil {
		return nil, err
	}
	// The fixed private bundle's 128 KiB JSON is base64 encoded by Secret.
	if permissionJSON(raw, 256<<10, 192<<10) != nil {
		clear(raw)
		return nil, cfg.ErrUnavailable
	}
	return raw, nil
}

func bootstrapPassiveLocator(d contracts.InitialBootstrap, s contracts.InitialBootstrapState) contracts.InitialBootstrapPassiveLocator {
	if s.PassiveHistory == nil || s.PassiveHistory.Receipt == nil || s.Projection == nil {
		return contracts.InitialBootstrapPassiveLocator{}
	}
	return contracts.InitialBootstrapPassiveLocator{Format: contracts.InitialBootstrapPassiveBundleFormat, SeedUID: s.SeedUID, InstallationID: s.InstallationID, RequestID: s.RequestID, ClusterID: s.ClusterID, Projection: *s.Projection, History: contracts.WorkerObjectReference{Name: bootstrapNames(d).passiveHistory, UID: s.PassiveHistory.Receipt.UID}, OperationID: s.PassiveHistory.OperationID}
}

func bootstrapSeedAnnotations(d contracts.InitialBootstrap, s contracts.InitialBootstrapState) map[string]string {
	a := map[string]string{initialBootstrapAnnotation: bootstrapDigest(d)}
	if !contracts.InitialBootstrapHasPassiveHistory(d.Format) || s.PassiveHistory == nil || s.PassiveHistory.Receipt == nil {
		return a
	}
	b, _ := json.Marshal(bootstrapPassiveLocator(d, s))
	a[initialBootstrapPassiveAnnotation] = string(b)
	if s.Manager != nil && s.Manager.RetiredAt != nil {
		if contracts.InitialBootstrapHasCopyClosure(d.Format) {
			b, _ := json.Marshal(contracts.InitialBootstrapManagerRetirement{OperationID: s.Manager.Closing.OperationID, Manager: *s.Manager.Receipt, StartedAt: s.Manager.Closing.StartedAt, Until: s.Manager.Closing.Until, RetiredAt: *s.Manager.RetiredAt})
			a[initialBootstrapRetiredAnnotation] = string(b)
		} else {
			a[initialBootstrapRetiredAnnotation] = s.Manager.RetiredAt.UTC().Format(time.RFC3339Nano)
		}
	}
	return a
}

func bootstrapPassiveLocatorValid(d contracts.InitialBootstrap, v contracts.InitialBootstrapPassiveLocator, seedUID string) bool {
	return contracts.InitialBootstrapHasPassiveHistory(d.Format) && v.Format == contracts.InitialBootstrapPassiveBundleFormat && v.SeedUID == seedUID && authorization.UUID(seedUID) && authorization.UUID(v.InstallationID) && authorization.UUID(v.RequestID) && authorization.UUID(v.ClusterID) && authorization.UUID(v.OperationID) && v.Projection.Name == bootstrapNames(d).projection && authorization.UUID(v.Projection.UID) && v.History.Name == bootstrapNames(d).passiveHistory && authorization.UUID(v.History.UID)
}

func bootstrapPassiveObject(d contracts.InitialBootstrap, s contracts.InitialBootstrapState, c contracts.InitialPreparer) (*core.Secret, error) {
	if !contracts.InitialBootstrapHasPassiveHistory(d.Format) || s.PassiveHistory == nil || s.Projection == nil || s.SeedUID == "" {
		return nil, cfg.ErrInvalid
	}
	observation, err := bootstrapObservationValue(d, s, c)
	if err != nil {
		return nil, err
	}
	name := "asservat_init_" + strings.ReplaceAll(s.InstallationID, "-", "") + "_history"
	v := contracts.InitialBootstrapPassiveBundle{Format: contracts.InitialBootstrapPassiveBundleFormat, Seed: contracts.WorkerObjectReference{Name: bootstrapNames(d).seed, UID: s.SeedUID}, Configuration: c, Observation: observation, History: contracts.OwnerSQLCredential{Username: name, Password: s.Passwords.History}}
	body, err := json.Marshal(v)
	if err != nil || len(body) > contracts.InitialBootstrapPassiveBundleMaxBytes {
		clear(body)
		return nil, cfg.ErrInvalid
	}
	m := bootstrapMeta(d, bootstrapNames(d).passiveHistory)
	m.Annotations["asservat.io/bootstrap-operation-id"] = s.PassiveHistory.OperationID
	return &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: m, Immutable: ptr.To(true), Type: core.SecretTypeOpaque, Data: map[string][]byte{"history.json": body}}, nil
}

// PreparePassiveHistory adds one fixed original create to the trusted producer.
// Its immutable receipt and metadata-only locator commit together. Unknown
// replies permit exact lookup only, including after process restart.
func (s *InitialBootstrap) PreparePassiveHistory(ctx context.Context) error {
	bounded, end, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer end()
	if !contracts.InitialBootstrapHasPassiveHistory(s.desired.Format) {
		return cfg.ErrInvalid
	}
	if err = s.current(bounded); err != nil {
		return err
	}
	secret, state, err := s.readSeed(bounded)
	if err != nil || state.Manager == nil || state.Manager.Closing != nil || state.Manager.RetiredAt != nil || state.Projection == nil {
		return cfg.ErrChanged
	}
	c, ready, err := s.readProjection(bounded, state)
	if err != nil || !ready {
		return cfg.ErrUnavailable
	}
	original := state
	fresh := state.PassiveHistory == nil
	if fresh {
		// The additional private copy shares the original setup interval.
		// Later exact receipt recovery performs no CREATE and cannot renew it.
		if !time.Now().Before(state.Manager.Until) {
			return cfg.ErrUnavailable
		}
		var stop context.CancelFunc
		bounded, stop = context.WithDeadline(bounded, state.Manager.Until)
		defer stop()
		id, err := prepUUID()
		if err != nil {
			return err
		}
		state.PassiveHistory = &contracts.InitialBootstrapCreate{Step: "passive-history", OperationID: id}
	}
	want, err := bootstrapPassiveObject(s.desired, state, c)
	if err != nil {
		return err
	}
	defer clear(want.Data["history.json"])
	if fresh {
		if err = s.updateSeed(bounded, secret, original, state); err != nil {
			return err
		}
	}
	path := "/api/v1/namespaces/" + s.desired.BootstrapNamespace + "/secrets"
	raw, err := s.getPassiveSecret(bounded)
	if apierrors.IsNotFound(err) && fresh {
		if err = s.current(bounded); err != nil {
			return err
		}
		raw, err = s.api.Post().AbsPath(path).Param("fieldValidation", "Strict").Body(want).MaxRetries(0).DoRaw(bounded)
		if err != nil {
			raw, err = s.getPassiveSecret(bounded)
		}
	} else if err == nil && fresh {
		return cfg.ErrChanged
	}
	defer clear(raw)
	var got core.Secret
	if err != nil || permissionJSON(raw, 256<<10, 192<<10) != nil || strictGuardJSON(raw, &got) != nil {
		return cfg.ErrUnavailable
	}
	defer clear(got.Data["history.json"])
	if !bootstrapObjectMatches(want, &got) {
		return cfg.ErrChanged
	}
	if state.PassiveHistory.Receipt != nil {
		if state.PassiveHistory.Receipt.UID != string(got.UID) || state.PassiveHistory.Receipt.ResourceVersion != got.ResourceVersion {
			return cfg.ErrChanged
		}
		return s.current(bounded)
	}
	secret, current, err := s.readSeed(bounded)
	if err != nil || !equalJSON(current, state) {
		return cfg.ErrChanged
	}
	next := state
	p := *state.PassiveHistory
	p.Receipt = &contracts.InitialPreparationReceipt{UID: string(got.UID), ResourceVersion: got.ResourceVersion}
	next.PassiveHistory = &p
	return s.updateSeed(bounded, secret, state, next)
}

type InitialBootstrapPassiveRead struct {
	Bundle contracts.InitialBootstrapPassiveBundle
	// ManagerRetired is only a retained positive cleanup disposition. It
	// authorizes no effects; callers still verify current protected history.
	ManagerRetired    bool
	ManagerRetirement *contracts.InitialBootstrapManagerRetirement
	Copies            *InitialBootstrapCopyState
	ValidUntil        time.Time
}

// readPassiveMetadata never negotiates a full Secret fallback. Unknown,
// unsupported or incorrectly typed responses deny before any broad seed read.
func (s *InitialBootstrap) readPassiveMetadata(ctx context.Context) (*meta.PartialObjectMetadata, *contracts.InitialBootstrapPassiveLocator, error) {
	path := "/api/v1/namespaces/" + s.desired.BootstrapNamespace + "/secrets/" + bootstrapNames(s.desired).seed
	raw, err := s.api.Get().AbsPath(path).SetHeader("Accept", bootstrapPartialMetadataAccept).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return nil, nil, err
	}
	var m meta.PartialObjectMetadata
	limit := 8 << 10
	if contracts.InitialBootstrapHasCopyClosure(s.desired.Format) {
		limit = 16 << 10
	}
	if permissionJSON(raw, limit, 4096) != nil || strictGuardJSON(raw, &m) != nil || m.APIVersion != "meta.k8s.io/v1" || m.Kind != "PartialObjectMetadata" || m.Name != bootstrapNames(s.desired).seed || m.Namespace != s.desired.BootstrapNamespace || !authorization.UUID(string(m.UID)) || !identity.Text(m.ResourceVersion, 128) || m.DeletionTimestamp != nil || len(m.OwnerReferences) != 0 || len(m.Finalizers) != 0 || len(m.Labels) != 0 || m.Annotations[initialBootstrapAnnotation] != bootstrapDigest(s.desired) || s.seedUID != "" && s.seedUID != string(m.UID) {
		return nil, nil, cfg.ErrChanged
	}
	for k := range m.Annotations {
		if k != initialBootstrapAnnotation && k != initialBootstrapPassiveAnnotation && k != initialBootstrapRetiredAnnotation && (!contracts.InitialBootstrapHasCopyClosure(s.desired.Format) || !slices.Contains(bootstrapCopyAnnotations(), k)) {
			return nil, nil, cfg.ErrChanged
		}
	}
	text := m.Annotations[initialBootstrapPassiveAnnotation]
	if text == "" {
		if len(m.Annotations) != 1 {
			return nil, nil, cfg.ErrChanged
		}
		return &m, nil, nil
	}
	v, err := contracts.DecodeInitialBootstrapPassiveLocator(strings.NewReader(text))
	if err != nil || !bootstrapPassiveLocatorValid(s.desired, v, string(m.UID)) {
		return nil, nil, cfg.ErrChanged
	}
	if retired, ok := m.Annotations[initialBootstrapRetiredAnnotation]; ok {
		if contracts.InitialBootstrapHasCopyClosure(s.desired.Format) {
			v, err := contracts.DecodeInitialBootstrapManagerRetirement(strings.NewReader(retired))
			if err != nil || !bootstrapManagerRetirementValid(v) {
				return nil, nil, cfg.ErrChanged
			}
		} else {
			at, err := time.Parse(time.RFC3339Nano, retired)
			if err != nil || !initialHandoverTime(at) || at.After(time.Now()) || retired != at.UTC().Format(time.RFC3339Nano) {
				return nil, nil, cfg.ErrChanged
			}
		}
	}
	return &m, &v, nil
}

// ReadPassiveHistory precedes every broad seed/SQL/provider path in the fixed
// installer. nil is returned only while original effect roots are absent.
// A completed or unknown existing installation never recreates a lost bundle.
func (s *InitialBootstrap) ReadPassiveHistory(ctx context.Context) (*InitialBootstrapPassiveRead, error) {
	bounded, end, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer end()
	if !contracts.InitialBootstrapHasPassiveHistory(s.desired.Format) {
		return nil, cfg.ErrInvalid
	}
	if err = s.administrator(bounded); err != nil {
		return nil, err
	}
	if _, err = s.namespace(bounded); err != nil {
		return nil, err
	}
	m, locator, err := s.readPassiveMetadata(bounded)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
	if locator == nil {
		// The new command creates/acknowledges its bundle before either effect
		// root may exist. Their presence requires exact passive recovery, not
		// another broad seed read or a new history login/Secret.
		for _, path := range []string{"/api/v1/namespaces/" + s.desired.TargetNamespace, "/api/v1/namespaces/" + s.desired.BootstrapNamespace + "/configmaps/" + bootstrapNames(s.desired).root} {
			_, err := s.get(bounded, path)
			if !apierrors.IsNotFound(err) {
				return nil, cfg.ErrChanged
			}
		}
		if bounded.Err() != nil {
			return nil, cfg.ErrUnavailable
		}
		if m != nil {
			s.seedUID = string(m.UID)
		}
		return nil, nil
	}
	raw, err := s.getPassiveSecret(bounded)
	defer clear(raw)
	var secret core.Secret
	if err != nil || strictGuardJSON(raw, &secret) != nil || string(secret.UID) != locator.History.UID {
		return nil, cfg.ErrChanged
	}
	defer clear(secret.Data["history.json"])
	v, err := contracts.DecodeInitialBootstrapPassiveBundle(bytes.NewReader(secret.Data["history.json"]))
	if err != nil || v.Format != contracts.InitialBootstrapPassiveBundleFormat || v.Seed.Name != bootstrapNames(s.desired).seed || v.Seed.UID != string(m.UID) || !equalJSON(v.Observation.Desired, s.desired) || v.Observation.InstallationID != locator.InstallationID || v.Observation.RequestID != locator.RequestID || v.Observation.ClusterID != locator.ClusterID || v.Observation.Projection != locator.Projection || !bootstrapObservationMatches(v.Observation, v.Configuration) || v.History.Username != "asservat_init_"+strings.ReplaceAll(locator.InstallationID, "-", "")+"_history" || !bootstrapPasswordValid(v.History.Password) {
		return nil, cfg.ErrChanged
	}
	metadata := bootstrapMeta(s.desired, locator.History.Name)
	metadata.Annotations["asservat.io/bootstrap-operation-id"] = locator.OperationID
	want := &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metadata, Immutable: ptr.To(true), Type: core.SecretTypeOpaque, Data: map[string][]byte{"history.json": secret.Data["history.json"]}}
	if !bootstrapObjectMatches(want, &secret) {
		return nil, cfg.ErrChanged
	}
	if contracts.InitialBootstrapHasCopyClosure(s.desired.Format) {
		// The outer enter owns and joins this observation. Reuse only the current
		// observation-only credential; each read still proves the original public
		// projection and native denial. No credential issuance per cleanup step.
		public := &InitialBootstrapObserver{bootstrap: s, projection: v.Observation, configuration: v.Configuration}
		if err = public.currentPublic(bounded); err != nil {
			return nil, err
		}
		if err = s.qualify(bounded, v.Observation.Prelude, v.Observation.ClusterID); err != nil {
			return nil, err
		}
		if err = public.currentPublic(bounded); err != nil {
			return nil, err
		}
	} else {
		observer, err := NewInitialBootstrapObserver(bounded, s.config, v.Observation, v.Configuration)
		if err != nil {
			return nil, err
		}
		defer observer.Close()
		token, err := observer.ReadToken(bounded)
		clear(token)
		if err != nil {
			return nil, err
		}
	}
	current, again, err := s.readPassiveMetadata(bounded)
	if err != nil || current.UID != m.UID || !equalJSON(again, locator) || !equalJSON(current.Annotations, m.Annotations) || bounded.Err() != nil {
		return nil, cfg.ErrChanged
	}
	s.seedUID = string(m.UID)
	until, _ := bounded.Deadline()
	result := &InitialBootstrapPassiveRead{Bundle: v, ManagerRetired: m.Annotations[initialBootstrapRetiredAnnotation] != "", ValidUntil: until}
	if contracts.InitialBootstrapHasCopyClosure(s.desired.Format) {
		if result.ManagerRetired {
			retired, err := contracts.DecodeInitialBootstrapManagerRetirement(strings.NewReader(m.Annotations[initialBootstrapRetiredAnnotation]))
			if err != nil || v.Configuration.Plan.HistoryManager == nil || retired.Manager != *v.Configuration.Plan.HistoryManager {
				return nil, cfg.ErrChanged
			}
			result.ManagerRetirement = &retired
		}
		result.Copies, err = bootstrapReadCopyState(s.desired, m, result)
		if err != nil {
			return nil, err
		}
		if result.Copies != nil && result.Copies.Policy != nil && result.Copies.Binding != nil {
			if err = s.copyCurrent(bounded, result, result.Copies); err != nil {
				return nil, err
			}
		}
	}
	if bounded.Err() != nil {
		return nil, cfg.ErrUnavailable
	}
	return result, nil
}
