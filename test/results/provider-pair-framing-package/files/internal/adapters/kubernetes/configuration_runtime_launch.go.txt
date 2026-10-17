package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"reflect"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

const configurationLaunchAnnotation = "asservat.io/configuration-launch-id"

func configurationLaunchValid(in contracts.ConfigurationRuntimeRoles, state contracts.ConfigurationRuntimeRoleState, ids map[string]bool, now time.Time) bool {
	l := state.Launch
	if l == nil || state.Projection == nil || state.Projection.SecretUID == "" || l.ProjectionUID != state.Projection.SecretUID || !authorization.UUID(l.OperationID) || ids[l.OperationID] || l.ClaimedAt.Before(state.CreatedAt) || l.ClaimedAt.After(now) || !l.ClaimedAt.Equal(l.ClaimedAt.Truncate(time.Microsecond)) || !l.Until.After(l.ClaimedAt) || l.Until.Sub(l.ClaimedAt) > 5*time.Second || l.Until.After(state.Until) || l.Until.After(l.Sources.FreshUntil) || !configurationRoleSourceMatches(in, l.Sources, l.ClaimedAt) || !configurationLaunchVersion(l.InertResourceVersion) {
		return false
	}
	d, err := hex.DecodeString(l.RunningDigest)
	if err != nil || len(d) != 32 || hex.EncodeToString(d) != l.RunningDigest || l.RunningDigest == strings.Repeat("0", 64) || l.RunningDigest == l.Sources.WorkloadDigest {
		return false
	}
	for _, ref := range []contracts.WorkerObjectReference{l.Configuration, l.Providers} {
		if !installationRefValid(ref.Name, ref.UID) || !authorization.UUID(ref.UID) {
			return false
		}
	}
	if l.Configuration.Name == in.FleetSource.Name || l.Configuration.Name == in.OwnerSource.Name || l.Configuration.UID == l.Providers.UID || l.Providers.UID == l.ProjectionUID {
		return false
	}
	for _, r := range state.Roles {
		if r.Claim == nil || r.Receipt == nil || !configurationRoleSameSources(r.Claim.Sources, l.Sources) {
			return false
		}
	}
	if r := l.Receipt; r != nil {
		if !configurationLaunchVersion(r.ResourceVersion) || r.ResourceVersion == l.InertResourceVersion || r.ObservedAt.Before(l.ClaimedAt) || r.ObservedAt.After(now) || !r.ObservedAt.Equal(r.ObservedAt.Truncate(time.Microsecond)) {
			return false
		}
	}
	return true
}

func configurationLaunchVersion(s string) bool {
	return len(s) > 0 && len(s) <= 128 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}

func configurationLaunchSources(current contracts.ConfigurationRoleObservation, l *contracts.ConfigurationRuntimeLaunch) bool {
	if l == nil || current.WorkloadDigest != l.RunningDigest {
		return false
	}
	// Only the exact pre-recorded specification transition is permitted.
	// Original role claims and their complete source values never change.
	current.WorkloadDigest = l.Sources.WorkloadDigest
	return configurationRoleSameSources(current, l.Sources)
}

func configurationLaunchSpec(d apps.Deployment, input contracts.ConfigurationRuntimeRoles, l *contracts.ConfigurationRuntimeLaunch) bool {
	if !configurationRoleDeploymentBound(d, input) || l == nil || *d.Spec.Replicas != 1 || d.ResourceVersion == l.InertResourceVersion || d.Annotations[configurationLaunchAnnotation] != l.OperationID {
		return false
	}
	b, err := json.Marshal(d.Spec)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(b)
	if hex.EncodeToString(digest[:]) != l.RunningDigest {
		return false
	}
	// Verify the running digest was really derived by the sole allowed edit,
	// not just copied from an unrelated running Deployment into the receipt.
	original := d.DeepCopy()
	*original.Spec.Replicas = 0
	b, err = json.Marshal(original.Spec)
	if err != nil {
		return false
	}
	digest = sha256.Sum256(b)
	return hex.EncodeToString(digest[:]) == l.Sources.WorkloadDigest
}

// This is an observation-only phase boundary. It deliberately does not reuse
// the inert operation's proof slot after changing replicas. A new current proof
// may verify the original result but never issue another launch or credential.
func (s *ConfigurationRuntimeRoleRoot) ReadLaunchedConfigurationRuntimeRoles(ctx context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error) {
	var zero contracts.ConfigurationRuntimeRoleSnapshot
	call, end, err := s.enter(ctx)
	if err != nil {
		return zero, err
	}
	defer end()
	state, _, err := s.read(call)
	if err != nil || state.State.Launch == nil || !configurationLaunchSources(state.Sources, state.State.Launch) {
		return zero, cfg.ErrUnavailable
	}
	call, stop := context.WithDeadline(call, state.ValidUntil)
	defer stop()
	if err = s.checkConfigurationLaunchObjects(call, state); err != nil {
		return zero, err
	}
	// This is a passive exact read. Keep the complete original post-lock
	// proof and recheck its time after the blocking reads. A later receipt CAS
	// performs its own full current enforcement/source check before mutation.
	if call.Err() != nil || !s.client.now().Before(state.ValidUntil) || !configurationRoleSourceMatches(s.input, state.Sources, s.client.now()) {
		return zero, cfg.ErrUnavailable
	}
	return state, nil
}

func (s *ConfigurationRuntimeRoleRoot) checkConfigurationLaunchObjects(ctx context.Context, state contracts.ConfigurationRuntimeRoleSnapshot) error {
	l := state.State.Launch
	if l == nil {
		return cfg.ErrUnavailable
	}
	var deployment apps.Deployment
	if s.readLaunchObject(ctx, "/apis/apps/v1/namespaces/"+s.input.Namespace.Name+"/deployments/"+s.input.Deployment.Name, &deployment) != nil || deployment.APIVersion != "apps/v1" || deployment.Kind != "Deployment" || !configurationLaunchSpec(deployment, s.input, l) {
		return cfg.ErrChanged
	}
	return s.configurationLaunchedInputs(ctx, state, deployment)
}

func (s *ConfigurationRuntimeRoleRoot) readLaunchObject(ctx context.Context, path string, out any) error {
	b, err := s.client.api.Get().AbsPath(path).MaxRetries(0).DoRaw(ctx)
	defer clear(b)
	if err != nil || permissionJSON(b, permissionPageBytes, 131072) != nil || strictGuardJSON(b, out) != nil || ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	if until, ok := ctx.Deadline(); !ok || !s.client.now().Before(until) {
		return cfg.ErrUnavailable
	}
	return nil
}

func (s *ConfigurationRuntimeRoleRoot) readConfigurationLaunchInput(ctx context.Context, state contracts.ConfigurationRuntimeRoleSnapshot) (contracts.HubWorkerDeployment, core.ConfigMap, error) {
	var zero contracts.HubWorkerDeployment
	l := state.State.Launch
	if l == nil {
		return zero, core.ConfigMap{}, cfg.ErrUnavailable
	}
	read := func(path string, out any) error { return s.readLaunchObject(ctx, path, out) }
	prefix := "/api/v1/namespaces/" + s.input.Namespace.Name
	var config core.ConfigMap
	if err := read(prefix+"/configmaps/"+l.Configuration.Name, &config); err != nil {
		return zero, core.ConfigMap{}, err
	}
	if config.APIVersion != "v1" || config.Kind != "ConfigMap" || !ownerMetadata(config.ObjectMeta, s.input.Namespace.Name, l.Configuration.Name, l.Configuration.UID) || config.Immutable == nil || !*config.Immutable || len(config.Data) != 1 || len(config.BinaryData) != 0 {
		return zero, core.ConfigMap{}, cfg.ErrChanged
	}
	input, err := contracts.DecodeHubWorkerDeployment(strings.NewReader(config.Data["deployment.json"]))
	if err != nil || input.Format != contracts.HubWorkerDeploymentFormat || input.InstallationID != s.input.InstallationID || input.ClusterID != s.input.ClusterID || input.Namespace != s.input.Namespace || input.FleetSource != s.input.FleetSource || input.OwnerSource != s.input.OwnerSource {
		return zero, core.ConfigMap{}, cfg.ErrChanged
	}
	return input, config, nil
}

// The legacy effect entry cannot acquire a provider2 launch by recognising its
// filenames or public profile. The concrete protected provider predecessor must
// supply its separate current setup/backing checks before that path can exist.
func (s *ConfigurationRuntimeRoleRoot) configurationLaunchInputs(ctx context.Context, state contracts.ConfigurationRuntimeRoleSnapshot, deployment apps.Deployment) error {
	input, _, err := s.readConfigurationLaunchInput(ctx, state)
	if err != nil {
		return err
	}
	if input.ProviderAuthentication != nil || input.ProviderInputs != nil {
		return cfg.ErrUnavailable
	}
	return s.configurationLegacyLaunchInputs(ctx, state, deployment, input)
}

func (s *ConfigurationRuntimeRoleRoot) configurationLegacyLaunchInputs(ctx context.Context, state contracts.ConfigurationRuntimeRoleSnapshot, deployment apps.Deployment, input contracts.HubWorkerDeployment) error {
	l := state.State.Launch
	prefix := "/api/v1/namespaces/" + s.input.Namespace.Name
	read := func(path string, out any) error { return s.readLaunchObject(ctx, path, out) }

	if !configurationLaunchMounts(deployment, input, l) {
		return cfg.ErrChanged
	}
	var providers core.Secret
	if read(prefix+"/secrets/"+l.Providers.Name, &providers) != nil {
		return cfg.ErrUnavailable
	}
	defer clearRuntimeProjection(providers.Data)
	if providers.APIVersion != "v1" || providers.Kind != "Secret" || !ownerMetadata(providers.ObjectMeta, s.input.Namespace.Name, l.Providers.Name, l.Providers.UID) || providers.Immutable == nil || !*providers.Immutable || providers.Type != core.SecretTypeOpaque || len(providers.Data) != 3 || len(providers.StringData) != 0 || len(providers.OwnerReferences) != 0 || len(providers.Finalizers) != 0 {
		return cfg.ErrChanged
	}
	for _, name := range []string{"audit-storage.json", "audit-wrap.token", "audit-unwrap.token"} {
		if len(providers.Data[name]) == 0 {
			return cfg.ErrChanged
		}
	}
	return s.configurationLaunchProjection(ctx, state)
}

func (s *ConfigurationRuntimeRoleRoot) configurationLaunchProjection(ctx context.Context, state contracts.ConfigurationRuntimeRoleSnapshot) error {
	l := state.State.Launch
	data, err := configurationProjectionData(state.State)
	if err != nil {
		return err
	}
	defer clearRuntimeProjection(data)
	manifest, err := configurationProjectionManifest(state)
	if err != nil {
		return err
	}
	data[contracts.ConfigurationRuntimeRoleManifestFile] = manifest
	ref, err := s.projection(ctx, state, data)
	if err != nil || ref.UID != l.ProjectionUID || ctx.Err() != nil || !s.client.now().Before(state.ValidUntil) || !configurationRoleSourceMatches(s.input, state.Sources, s.client.now()) {
		return cfg.ErrUnavailable
	}
	return nil
}

func configurationLaunchMounts(d apps.Deployment, input contracts.HubWorkerDeployment, l *contracts.ConfigurationRuntimeLaunch) bool {
	if l == nil || len(d.Spec.Template.Spec.Containers) != 1 || len(d.Spec.Template.Spec.InitContainers) != 0 || len(d.Spec.Template.Spec.EphemeralContainers) != 0 {
		return false
	}
	c := d.Spec.Template.Spec.Containers[0]
	buildWorker := BuildProvisionedHubWorkerWorkload
	if input.Activation != nil {
		if !HubWorkerActivationBound(input) {
			return false
		}
		buildWorker = BuildInstalledHubWorkerWorkload
	}
	w, err := buildWorker(HubWorkerWorkloadPlan{
		Namespace: d.Namespace, Name: d.Name, ServiceAccount: d.Spec.Template.Spec.ServiceAccountName,
		Configuration: l.Configuration.Name, Credentials: l.Providers.Name, Image: c.Image,
		FleetSource: input.FleetSource.Name, OwnerSource: input.OwnerSource.Name,
		FleetGuard: input.FleetGuard.Name, OwnerGuard: input.OwnerGuard.Name, LeaderLease: input.LeaderLease.Name,
	}, input.InstallationID)
	if err != nil {
		return false
	}
	// These explicitly populated fields have no server-default ambiguity. The
	// original guarded full-spec digest additionally pins every other field.
	expected := w.Deployment.Spec.Template.Spec
	return equalJSON(d.Spec.Template.Spec.Volumes, expected.Volumes) && equalJSON(c.VolumeMounts, expected.Containers[0].VolumeMounts) && equalJSON(c.Command, expected.Containers[0].Command) && equalJSON(c.Env, expected.Containers[0].Env) && len(c.Args) == 0 && len(c.EnvFrom) == 0
}

// LaunchConfigurationRuntime issues only the original exact zero-to-one CAS.
// A retained launch disposition always denies this effect path. The installer
// must use the separate read-only verifier to reconcile a running result.
// The supplied snapshot comes from the actual current SQL verifier and keeps
// that original interval through all native input/protection reads below.
func (s *ConfigurationRuntimeRoleRoot) LaunchConfigurationRuntime(ctx context.Context, verified contracts.ConfigurationRuntimeRoleSnapshot, configuration, providers contracts.WorkerObjectReference) error {
	return s.launchConfigurationRuntime(ctx, verified, configuration, providers, nil)
}

// The provider check is private and can only be composed by the concrete
// original worker-input publisher. Legacy callers cannot supply a callback or
// recognize a profile to bypass their original static-token input checks.
func (s *ConfigurationRuntimeRoleRoot) launchConfigurationRuntime(ctx context.Context, verified contracts.ConfigurationRuntimeRoleSnapshot, configuration, providers contracts.WorkerObjectReference, provider *configurationWorkerLaunchCheck) error {
	call, end, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer end()
	old, object, err := s.read(call)
	if err != nil {
		return err
	}
	if old.State.Launch != nil || old.State.Projection == nil || old.State.Projection.SecretUID == "" || old.UID != verified.UID || old.State.OperationID != verified.State.OperationID || !reflect.DeepEqual(old.State, verified.State) || !configurationRoleSameSources(old.Sources, verified.Sources) {
		return cfg.ErrChanged
	}
	until := old.ValidUntil
	for _, d := range []time.Time{verified.ValidUntil, old.State.Until} {
		if d.Before(until) {
			until = d
		}
	}
	until = until.UTC().Truncate(time.Microsecond)
	call, stop := context.WithDeadline(call, until)
	defer stop()
	if call.Err() != nil || !s.client.now().Before(until) {
		return cfg.ErrUnavailable
	}
	path := "/apis/apps/v1/namespaces/" + s.input.Namespace.Name + "/deployments/" + s.input.Deployment.Name
	var inert apps.Deployment
	if s.readLaunchObject(call, path, &inert) != nil || inert.APIVersion != "apps/v1" || inert.Kind != "Deployment" || !configurationRoleDeploymentBound(inert, s.input) || *inert.Spec.Replicas != 0 || inert.Annotations[configurationLaunchAnnotation] != "" {
		return cfg.ErrChanged
	}
	b, err := json.Marshal(inert.Spec)
	if err != nil {
		return cfg.ErrUnavailable
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != old.Sources.WorkloadDigest {
		return cfg.ErrChanged
	}
	running := inert.DeepCopy()
	*running.Spec.Replicas = 1
	b, err = json.Marshal(running.Spec)
	if err != nil {
		return cfg.ErrUnavailable
	}
	h = sha256.Sum256(b)
	launch := &contracts.ConfigurationRuntimeLaunch{OperationID: uuid.NewString(), ClaimedAt: s.client.now().UTC().Truncate(time.Microsecond), Until: until, Sources: old.Sources, InertResourceVersion: inert.ResourceVersion, RunningDigest: hex.EncodeToString(h[:]), ProjectionUID: old.State.Projection.SecretUID, Configuration: configuration, Providers: providers}
	candidate := old
	candidate.State.Launch = launch
	if !configurationRoleStateValid(s.input, candidate.State, s.client.now()) {
		return cfg.ErrInvalid
	}
	if provider == nil {
		err = s.configurationLaunchInputs(call, candidate, *running)
	} else {
		err = provider.before(call, s, candidate, *running)
	}
	if err != nil {
		return err
	}
	// This CAS spends the one attempt; it grants no workload effect. A source
	// change during the input reads may leave this attempt spent, but the
	// mandatory complete current check below still precedes Deployment PUT.
	claimed, err := s.update(call, old, object, candidate.State, until)
	if err != nil {
		return err
	} // Unknown root CAS never authorizes Deployment PUT.
	// Final current check after the root CAS. The original Deployment RV is
	// deliberately retained even if an unrelated controller status write wins.
	current, err := s.source.ReadConfigurationRoleSource(call)
	if err != nil || !configurationRoleSameSources(current, old.Sources) || !reflect.DeepEqual(claimed.State.Launch, launch) || call.Err() != nil || !s.client.now().Before(until) {
		return cfg.ErrUnavailable
	}
	if current.FreshUntil.Before(until) {
		until = current.FreshUntil
	}
	effect, finish := context.WithDeadline(call, until)
	defer finish()
	if effect.Err() != nil || !s.client.now().Before(until) {
		return cfg.ErrUnavailable
	}
	if provider != nil {
		if err = provider.before(effect, s, claimed, *running); err != nil {
			return err
		}
	}
	if running.Annotations == nil {
		running.Annotations = map[string]string{}
	}
	running.Annotations[configurationLaunchAnnotation] = launch.OperationID
	raw, err := s.client.api.Put().AbsPath(path).Param("fieldValidation", "Strict").Body(running).MaxRetries(0).DoRaw(effect)
	defer clear(raw)
	if err != nil {
		return cfg.ErrUnavailable
	}
	var result apps.Deployment
	if permissionJSON(raw, permissionPageBytes, 131072) != nil || strictGuardJSON(raw, &result) != nil || result.APIVersion != "apps/v1" || result.Kind != "Deployment" || !configurationLaunchSpec(result, s.input, launch) || effect.Err() != nil {
		return cfg.ErrUnavailable
	}
	if provider != nil && !provider.current(effect) {
		return cfg.ErrUnavailable
	}
	// This acknowledges the one UPDATE only. Successful installation still
	// requires separately current SQL/native readback and the original receipt.
	return nil
}

// RecordConfigurationRuntimeLaunch accepts only a separately current exact
// read-only SQL inventory result. No missing/changed receipt restarts launch.
func (s *ConfigurationRuntimeRoleRoot) RecordConfigurationRuntimeLaunch(ctx context.Context, verified contracts.ConfigurationRuntimeRoleSnapshot) error {
	call, end, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer end()
	// Re-read only the exact retained state under the SQL verifier's original
	// post-lock proof. This read supplies no new authority. The full current
	// negative enforcement/source check below remains mandatory before CAS.
	current, object, err := s.readObserved(call, verified.Sources, verified.ObservedAt)
	if err != nil {
		return err
	}
	if current.State.Launch == nil || current.UID != verified.UID || !reflect.DeepEqual(current.State, verified.State) || !configurationRoleSameSources(current.Sources, verified.Sources) || !configurationLaunchSources(current.Sources, current.State.Launch) {
		return cfg.ErrChanged
	}
	until := current.ValidUntil
	if verified.ValidUntil.Before(until) {
		until = verified.ValidUntil
	}
	call, stop := context.WithDeadline(call, until)
	defer stop()
	if err = s.checkConfigurationLaunchObjects(call, current); err != nil {
		return err
	}
	if current.State.Launch.Receipt != nil {
		proof, e := s.source.ReadConfigurationRoleSource(call)
		if e != nil || !configurationRoleSameSources(proof, current.Sources) || call.Err() != nil || !s.client.now().Before(until) {
			return cfg.ErrUnavailable
		}
		return nil
	}
	var d apps.Deployment
	if s.readLaunchObject(call, "/apis/apps/v1/namespaces/"+s.input.Namespace.Name+"/deployments/"+s.input.Deployment.Name, &d) != nil || !configurationLaunchSpec(d, s.input, current.State.Launch) {
		return cfg.ErrChanged
	}
	proof, err := s.source.ReadConfigurationRoleSource(call)
	if err != nil || !configurationRoleSameSources(proof, current.Sources) || call.Err() != nil {
		return cfg.ErrUnavailable
	}
	if proof.FreshUntil.Before(until) {
		until = proof.FreshUntil
	}
	next := current.State
	launch := *next.Launch
	launch.Receipt = &contracts.ConfigurationRuntimeLaunchReceipt{ResourceVersion: d.ResourceVersion, ObservedAt: s.client.now().UTC().Truncate(time.Microsecond)}
	next.Launch = &launch
	if !configurationRoleStateValid(s.input, next, s.client.now()) {
		return cfg.ErrUnavailable
	}
	_, err = s.update(call, current, object, next, until)
	return err
}
