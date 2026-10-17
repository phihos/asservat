package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type directNativeRegionalSource struct {
	reader        *kube.ConnectorIdentitySource
	plan          cfg.ConfigMapAdministration
	pin           kube.GuardPin
	name, uid     string
	capacityPlan  cfg.CapacityNamespaceAdministration
	capacityPin   kube.GuardPin
	configuration app.ConnectorIdentityConfiguration
	observation   value.ConnectorObservationPin
}

// regionalSource creates the protected connector source for peer (a new ID
// when empty). stage selects fixture staging; ADR-193 bootstrap tests leave
// staging to the hub under bootstrap authority.
func (x *directNativeCluster) regionalSource(t *testing.T, ctx context.Context, l *directNativeSQL, root, installation, epoch, peer string, stage bool, clientCA, serverCA CA) *directNativeRegionalSource {
	t.Helper()
	if peer == "" {
		peer = custodyID()
	}
	binding := value.PeerBinding{InstallationID: installation, ClusterID: x.id, IssuerEpoch: epoch, PeerID: peer, Role: value.ConnectorPeer}
	backing, e := json.Marshal(l.backing)
	if e != nil {
		t.Fatal("native original backing encode")
	}
	d, a := x.deployments["regional"], x.accounts["regional"]
	roles := l.roles
	input := contracts.ConnectorIdentityConfiguration{Format: contracts.ConnectorIdentityFormat, RootID: root, InstallationID: installation, ClusterID: x.id, IssuerEpoch: epoch, PeerID: binding.PeerID, Revision: 1, ServerName: "connector.fixture.invalid", ClientIssuerRoots: [][]byte{clientCA.DER}, ServerIssuerRoots: [][]byte{serverCA.DER}, Roles: contracts.ConnectorIdentityRoles{Source: roles.Source, Journal: roles.Journal, Acknowledgement: roles.Acknowledgement, Cleanup: roles.Cleanup, Verifier: roles.Verifier, Finalizer: roles.Finalizer}, Deployment: contracts.ConnectorDeployment{Namespace: x.namespace.Name, NamespaceUID: string(x.namespace.UID), ServiceAccount: a.Name, AccountUID: string(a.UID), Deployment: d.Name, DeploymentUID: string(d.UID), ServingSlots: 2, RetainedProcesses: 8}, Backing: backing}
	raw, e := json.Marshal(input)
	if e != nil {
		t.Fatal("native connector source encode")
	}
	cm, e := x.api.CoreV1().ConfigMaps(x.namespace.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "connector-identity"}, Data: map[string]string{"connector-identity.json": string(raw)}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal("native connector source create", e)
	}
	out := &directNativeRegionalSource{name: cm.Name, uid: string(cm.UID), plan: cfg.ConfigMapAdministration{Name: x.namespace.Name + "-source", SourceName: cm.Name, ControlNamespace: x.plan.ControlNamespace, Administrators: x.plan.Administrators}}
	policy, bindingObject, e := kube.ConnectorIdentityAdmission(out.plan)
	if e != nil {
		t.Fatal("native connector source protection", e)
	}
	out.pin = x.installGuard(t, ctx, policy, bindingObject)
	out.capacityPlan = cfg.CapacityNamespaceAdministration{Name: x.namespace.Name + "-capacity", Administrators: x.plan.Administrators, Keys: []string{"native-team"}, ProbeNamespace: x.plan.ControlNamespace, ProbeAccount: cfg.NamespaceRef{Name: "probe", UID: string(x.accounts["probe"].UID)}}
	policy, bindingObject, e = kube.CapacityNamespaceAdmission(out.capacityPlan)
	if e != nil {
		t.Fatal("native selector guard", e)
	}
	out.capacityPin = x.installGuard(t, ctx, policy, bindingObject)
	observer, probe := x.clients(t)
	sourceGuard, e := kube.NewConnectorIdentityProtection(observer, probe, out.plan, out.pin)
	if e != nil {
		t.Fatal("native exact source guard", e)
	}
	out.reader, e = kube.NewConnectorIdentitySource(observer, sourceGuard, out.name, out.uid, root, binding)
	if e != nil {
		t.Fatal("native exact source constructor", e)
	}
	// Propagation polling is setup only, before source Stage or any key/effect.
	// It cannot replay a failed admission or lengthen a measured request.
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end); {
		out.configuration, e = out.reader.ReadConnectorIdentityConfiguration(ctx)
		if e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("native source setup cancelled")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if e != nil {
		t.Fatal("native original source unavailable", e)
	}
	out.observation = value.ConnectorObservationPin{Profile: out.configuration.Source.Observation.Profile.Clone(), Roles: out.configuration.Source.Roles, TemplateDigest: x.template(t, "regional"), ImageDigest: x.image, ProtectionDigest: x.protection}
	if !out.observation.Valid() {
		t.Fatal("native regional original pins invalid")
	}
	if stage {
		l.stageRegional(t, ctx, out.configuration)
	}
	return out
}

func directNativePopulate(in Input, owner value.OwnerObservationPin, caller value.ClusterObservationCallerPin, source *directNativeRegionalSource, ownerCA, clientCA, serverCA CA, l *directNativeSQL, dial string, credential directNativeClusterCredential) Input {
	in.Owner = owner
	in.Caller = caller
	in.ClusterCredential = credential.profile
	in.Regional = source.observation.Clone()
	in.OwnerCA = CA{DER: ownerCA.DER}
	in.ConnectorClientCA = CA{DER: clientCA.DER}
	in.ConnectorServerCA = CA{DER: serverCA.DER}
	switch in.Mode {
	case "owner":
		// ADR-169: the hub's connector duties, issuer and audit live here.
		in.OwnerCA = ownerCA
		in.Audit = l.audit
		in.ConnectorClientCA = clientCA
		in.ConnectorServerCA = serverCA
		in.ConnectorConfiguration = source.configuration.Clone()
		in.OperationMACKey = make([]byte, 32)
		in.AccountMACKey = make([]byte, 32)
		// These are explicit fixture audit/account keys, not product source values.
		for i := range in.OperationMACKey {
			in.OperationMACKey[i] = 31
			in.AccountMACKey[i] = 32
		}
	case "regional":
		in.LifecycleDial = credential.dial
		in.ClusterCredentialNamespace, in.ClusterCredentialSecret, in.ClusterCredentialSecretUID = credential.namespace, credential.secret, credential.uid
		in.ConnectorSourcePlan = source.plan
		in.ConnectorSourcePin = source.pin
		in.ConnectorSourceName = source.name
		in.ConnectorSourceUID = source.uid
		in.CapacityPlan = source.capacityPlan
		in.CapacityPin = source.capacityPin
		in.RegionalDial = dial
	}
	return in
}

// directNativeClusterCredential is the fixture's synthetic installer step for
// ADR-168: generation 1 enrolled in SQL and its seed in the one regional
// Secret. Neither the seed nor the Secret reaches the owner Pod.
type directNativeClusterCredential struct {
	profile                      value.ClusterCredentialProfile
	namespace, secret, uid, dial string
}

// bootstrapCredential creates the generation-0 Secret holding only the
// operator-delivered bootstrap envelope (ADR-193); the connector enrolls
// generation 1 itself.
func (x *directNativeCluster) bootstrapCredential(t *testing.T, ctx context.Context, envelope value.BootstrapEnvelope, profile value.ClusterCredentialProfile, dial string) directNativeClusterCredential {
	t.Helper()
	raw, e := json.Marshal(app.ClusterCredentialSecret{Bootstrap: &envelope})
	if e != nil {
		t.Fatal(e)
	}
	secret, e := x.api.CoreV1().Secrets(x.namespace.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "cluster-credential"}, Data: map[string][]byte{"cluster-credential.json": raw}}, meta.CreateOptions{})
	clear(raw)
	if e != nil {
		t.Fatal("native generation-0 cluster credential Secret", e)
	}
	return directNativeClusterCredential{profile: profile, namespace: x.namespace.Name, secret: secret.Name, uid: string(secret.UID), dial: dial}
}

func (x *directNativeCluster) clusterCredential(t *testing.T, ctx context.Context, l *directNativeSQL, profile value.ClusterCredentialProfile, dial string) directNativeClusterCredential {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, e := rand.Read(seed); e != nil {
		t.Fatal(e)
	}
	// ADR-193: generation 1 through the bootstrap functions; the claimed
	// bootstrap row is this fixture's synthetic setup authority.
	clusterBootstrapGenerationOne(t, ctx, l.lab.admin, l.pools["cluster-credential"], profile, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	raw, e := json.Marshal(app.ClusterCredentialSecret{Generation: 1, Seed: seed, RotatedAt: time.Now().UTC().Truncate(time.Microsecond)})
	if e != nil {
		t.Fatal(e)
	}
	secret, e := x.api.CoreV1().Secrets(x.namespace.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "cluster-credential"}, Data: map[string][]byte{"cluster-credential.json": raw}}, meta.CreateOptions{})
	clear(raw)
	if e != nil {
		t.Fatal("native cluster credential Secret", e)
	}
	return directNativeClusterCredential{profile: profile, namespace: x.namespace.Name, secret: secret.Name, uid: string(secret.UID), dial: dial}
}
