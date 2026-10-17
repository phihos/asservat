package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
)

// Projection-only incomplete source responses. No proof marker, accepted-reader
// interface or effect method exists on this type. Its enclosing original call
// owns every response and date through completion under the SQL bridge.
type ownerProjectionSourcePrefix struct {
	source                      *ConfigurationRoleSource
	started, until              time.Time
	guards                      [3]string
	fleet                       fleet.Administration
	owner                       fleet.OwnerConfiguration
	fleetRef, ownerRef          cfg.Resource
	deployment, ownerDeployment apps.Deployment
	account                     core.ServiceAccount
	administrator               auth.UserInfo
	actors                      [3]auth.UserInfo
}
type ownerProjectionSourceTail struct {
	fleet      fleet.Administration
	deployment apps.Deployment
	account    core.ServiceAccount
	until      time.Time
}

// Actual first half of the complete source graph; the ordinary full reader is
// unchanged. Returning this private prefix cannot authorize a claim or effect.
func (s *ConfigurationRoleSource) readOwnerProjectionSourcePrefix(ctx context.Context) (*ownerProjectionSourcePrefix, error) {
	var zero *ownerProjectionSourcePrefix
	if s == nil || ctx == nil || ctx.Err() != nil {
		return zero, configurationSourceError(configurationSourceEntry, cfg.ErrUnavailable)
	}
	started := s.client.now()
	call, cancel := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer cancel()
	until, _ := call.Deadline()
	ns, err := s.client.namespace(call, s.client.control)
	if err != nil {
		return zero, configurationSourceError(configurationSourceNamespaceFirstRead, err)
	}
	if ns.Deleting {
		return zero, configurationSourceError(configurationSourceNamespaceFirstDeleting, cfg.ErrChanged)
	}
	before, err := s.configurationRoleGuardVersions(call)
	if err != nil {
		return zero, configurationSourceError(configurationSourceGuardsFirst, err)
	}

	// Exactly three fixed independent probes. Cancellation is propagated on a
	// failure, but every started probe is joined before any result is used.
	probeCall, stopProbes := context.WithCancel(call)
	var probe sync.WaitGroup
	var sources [2]core.ConfigMap
	var ownerDeployment apps.Deployment
	var actors [3]auth.UserInfo
	var errors [3]error
	probe.Add(3)
	go func() {
		defer probe.Done()
		ownerDeployment, actors[0], errors[0] = s.protection.proveObjectIdentity(probeCall, started)
		if errors[0] != nil {
			stopProbes()
		}
	}()
	go func() {
		defer probe.Done()
		sources[0], actors[1], errors[1] = s.fleet.protection.proveObjectIdentity(probeCall)
		if errors[1] != nil {
			stopProbes()
		}
	}()
	go func() {
		defer probe.Done()
		sources[1], actors[2], errors[2] = s.owner.protection.proveObjectIdentity(probeCall)
		if errors[2] != nil {
			stopProbes()
		}
	}()
	probe.Wait()
	stopProbes()
	// Keep original branch-index precedence after all three probes join.
	for i, e := range errors {
		if e != nil {
			check := configurationSourceProbeWorkload
			if i == 1 {
				check = configurationSourceProbeFleet
			}
			if i == 2 {
				check = configurationSourceProbeOwner
			}
			return zero, configurationSourceError(check, e)
		}
	}
	administrator, err := s.configurationWorkerAdministrator(call)
	if err != nil {
		return zero, configurationSourceError(configurationSourceAdministrator, err)
	}
	f, fref, err := s.configurationWorkerFleet(sources[0], started)
	if err != nil {
		return zero, configurationSourceError(configurationSourceFleetInitial, err)
	}
	o, oref, rootsUntil, err := s.configurationWorkerOwner(sources[1])
	if err != nil {
		return zero, configurationSourceError(configurationSourceOwnerInitial, err)
	}
	until = identity.Earlier(until, identity.Earlier(f.FreshUntil, rootsUntil))
	call, narrow := context.WithDeadline(call, until)
	defer narrow()
	if !s.configurationWorkerSourcesMatch(f, o) {
		return zero, configurationSourceError(configurationSourceSourcePair, cfg.ErrChanged)
	}
	reader := &OwnerEndpoints{client: s.client, pool: o.Pool}
	deploymentPath := "/apis/apps/v1/namespaces/" + s.input.Namespace.Name + "/deployments/" + s.input.Deployment.Name
	accountPath := "/api/v1/namespaces/" + s.input.Namespace.Name + "/serviceaccounts/" + s.input.ServiceAccount.Name
	d, err := ownerResource[apps.Deployment](reader, call, deploymentPath, "apps/v1", "Deployment")
	if err != nil {
		return zero, configurationSourceError(configurationSourceDeploymentFirstRead, err)
	}
	if !configurationRoleDeploymentBound(d, s.input) {
		return zero, configurationSourceError(configurationSourceDeploymentFirstBound, cfg.ErrChanged)
	}
	account, err := ownerResource[core.ServiceAccount](reader, call, accountPath, "v1", "ServiceAccount")
	if err != nil {
		return zero, configurationSourceError(configurationSourceAccountFirstRead, err)
	}
	if !ownerMetadata(account.ObjectMeta, s.input.Namespace.Name, s.input.ServiceAccount.Name, s.input.ServiceAccount.UID) {
		return zero, configurationSourceError(configurationSourceAccountFirstBound, cfg.ErrChanged)
	}
	return &ownerProjectionSourcePrefix{source: s, started: started, until: until, guards: before, fleet: f, owner: o, fleetRef: fref, ownerRef: oref, deployment: d, account: account, ownerDeployment: ownerDeployment, administrator: administrator, actors: actors}, nil
}

// The second actual guard/source/workload reads happen only after bridge lock
// acquisition. The enclosing operation adds its current objects/journals before
// finish performs the trailing namespace and original-time checks.
func (p *ownerProjectionSourcePrefix) readTail(ctx context.Context) (ownerProjectionSourceTail, error) {
	var zero ownerProjectionSourceTail
	if p == nil || p.source == nil || ctx == nil {
		return zero, cfg.ErrUnavailable
	}
	if e := ctx.Err(); e != nil {
		return zero, configurationSourceError(contextCheck(e, configurationSourceTailExpired, configurationSourceTailCancelled), cfg.ErrUnavailable)
	}
	s := p.source
	deadline, ok := ctx.Deadline()
	if !ok {
		return zero, cfg.ErrUnavailable
	}
	until := identity.Earlier(p.until, deadline)
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	reader := &OwnerEndpoints{client: s.client, pool: p.owner.Pool}
	deploymentPath := "/apis/apps/v1/namespaces/" + s.input.Namespace.Name + "/deployments/" + s.input.Deployment.Name
	accountPath := "/api/v1/namespaces/" + s.input.Namespace.Name + "/serviceaccounts/" + s.input.ServiceAccount.Name
	guards, err := s.configurationRoleGuardVersions(call)
	if err != nil {
		return zero, configurationSourceError(configurationSourceGuardsFinal, err)
	}
	if guards != p.guards {
		return zero, configurationSourceError(configurationSourceGuardsChanged, cfg.ErrChanged)
	}
	lastFleet, lastOwner, lastFleetRef, lastOwnerRef, lastRootsUntil, err := s.readConfigurationWorkerValues(call, p.started)
	if err != nil {
		return zero, configurationSourceError(configurationSourceValuesFinal, err)
	}
	if lastFleet.Revision != p.fleet.Revision || !lastOwner.Equal(p.owner) || lastFleetRef != p.fleetRef || lastOwnerRef != p.ownerRef {
		return zero, configurationSourceError(configurationSourceSourcesChanged, cfg.ErrChanged)
	}
	until = identity.Earlier(until, lastRootsUntil)
	d2, err := ownerResource[apps.Deployment](reader, call, deploymentPath, "apps/v1", "Deployment")
	if err != nil {
		return zero, configurationSourceError(configurationSourceDeploymentFinalRead, err)
	}
	if !configurationRoleDeploymentBound(d2, s.input) || !equalJSON(p.deployment.Spec, d2.Spec) || p.deployment.ResourceVersion != d2.ResourceVersion {
		return zero, configurationSourceError(configurationSourceDeploymentFinalBound, cfg.ErrChanged)
	}
	account2, err := ownerResource[core.ServiceAccount](reader, call, accountPath, "v1", "ServiceAccount")
	if err != nil {
		return zero, configurationSourceError(configurationSourceAccountFinalRead, err)
	}
	if !ownerMetadata(account2.ObjectMeta, s.input.Namespace.Name, s.input.ServiceAccount.Name, s.input.ServiceAccount.UID) || p.account.ResourceVersion != account2.ResourceVersion || !equalJSON(p.account, account2) {
		return zero, configurationSourceError(configurationSourceAccountFinalBound, cfg.ErrChanged)
	}
	return ownerProjectionSourceTail{fleet: lastFleet, deployment: d2, account: account2, until: until}, nil
}

func (p *ownerProjectionSourcePrefix) finish(ctx context.Context, last ownerProjectionSourceTail) (configurationWorkerNative, error) {
	var zero configurationWorkerNative
	if p == nil || p.source == nil || ctx == nil {
		return zero, cfg.ErrUnavailable
	}
	if e := ctx.Err(); e != nil {
		return zero, configurationSourceError(contextCheck(e, configurationSourceFinishExpired, configurationSourceFinishCancelled), cfg.ErrUnavailable)
	}
	s := p.source
	deadline, ok := ctx.Deadline()
	if !ok {
		return zero, cfg.ErrUnavailable
	}
	until := identity.Earlier(deadline, identity.Earlier(p.until, last.until))
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	ns, err := s.client.namespace(call, s.client.control)
	if err != nil {
		return zero, configurationSourceError(configurationSourceNamespaceFinalRead, err)
	}
	if ns.Deleting {
		return zero, configurationSourceError(configurationSourceNamespaceFinalDeleting, cfg.ErrChanged)
	}
	// Split only the original short-circuit predicates; preserve every clock sample.
	if initialHandoverDeadline(call, s.client.now, until) != nil {
		return zero, configurationSourceError(configurationSourceFinalDeadline, cfg.ErrUnavailable)
	}
	if !p.fleet.Valid(s.client.now()) {
		return zero, configurationSourceError(configurationSourceInitialFleetValid, cfg.ErrUnavailable)
	}
	if !last.fleet.Valid(s.client.now()) {
		return zero, configurationSourceError(configurationSourceFinalFleetValid, cfg.ErrUnavailable)
	}
	encoded, err := json.Marshal(p.deployment.Spec)
	if err != nil {
		return zero, configurationSourceError(configurationSourceDeploymentEncode, cfg.ErrUnavailable)
	}
	digest := sha256.Sum256(encoded)
	revision := func(r identity.Revision) contracts.ConfigurationRoleSourceRevision {
		return contracts.ConfigurationRoleSourceRevision{UID: r.UID, Generation: r.Generation, Digest: hex.EncodeToString(r.Digest[:]), ObservedAt: p.started.UTC(), FreshUntil: until.UTC()}
	}
	observation := contracts.ConfigurationRoleObservation{InstallationID: s.input.InstallationID, ClusterID: s.input.ClusterID,
		IssuerEpoch: p.fleet.IssuerEpoch, NamespaceUID: s.input.Namespace.UID, DeploymentUID: s.input.Deployment.UID, AccountUID: s.input.ServiceAccount.UID,
		WorkloadDigest: hex.EncodeToString(digest[:]), GuardDigest: hex.EncodeToString(s.protection.digest[:]), Fleet: revision(p.fleet.Revision), Owner: revision(p.owner.Revision),
		ObservedAt: p.started.UTC(), FreshUntil: until.UTC()}
	if s.protection.digest == (artifact.Digest{}) {
		return zero, configurationSourceError(configurationSourceGuardDigest, cfg.ErrUnavailable)
	}
	if !configurationRoleSourceMatches(s.input, observation, s.client.now()) {
		return zero, configurationSourceError(configurationSourceObservationMatch, cfg.ErrUnavailable)
	}
	responses := &configurationRoleNativeResponses{clients: [3]*PermissionClient{s.protection.probe, s.fleet.protection.probe, s.owner.protection.probe}, identities: p.actors, worker: *last.account.DeepCopy()}
	return configurationWorkerNative{proof: configurationRoleObserved{observation: observation, deploymentVersion: p.deployment.ResourceVersion,
		accountVersion: p.account.ResourceVersion, guards: p.guards, native: responses}, fleet: p.fleet, owner: p.owner, deployment: last.deployment, account: last.account,
		administrator: p.administrator, fleetRef: p.fleetRef, ownerRef: p.ownerRef, ownerDeployment: p.ownerDeployment}, nil
}

// contextCheck names why a context ended without carrying its error text.
func contextCheck(e error, expired, cancelled configurationSourceCheck) configurationSourceCheck {
	if errors.Is(e, context.DeadlineExceeded) {
		return expired
	}
	return cancelled
}
