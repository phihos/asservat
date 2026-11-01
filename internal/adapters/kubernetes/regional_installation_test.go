package kubernetes

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
)

// ADR-193 step 5: the gated connector workload is Restricted and mounts no
// Secret; its RBAC names only its own objects; the plan must match the offer.
func TestRegionalInstallShape(t *testing.T) {
	offer := contracts.RegionalOffer{Format: contracts.RegionalOfferFormat, InstallationID: ownerID(1), PermissionRootID: ownerID(2), IssuerEpoch: ownerID(3), Image: "registry.invalid/asservat@sha256:" + "ab",
		Federation: contracts.RegionalHubEndpoint{Endpoint: "https://federation.invalid:443", ServerName: "federation.invalid", Roots: [][]byte{{1}}}, ConnectorIssuerRoots: [][]byte{{2}}, ConnectorBacking: []byte(`{}`)}
	d := RegionalWorkload(offer, false, false)
	spec := d.Spec.Template.Spec
	c := spec.Containers[0]
	if *d.Spec.Replicas != 0 || *spec.AutomountServiceAccountToken || !*spec.SecurityContext.RunAsNonRoot || *c.SecurityContext.AllowPrivilegeEscalation || !*c.SecurityContext.ReadOnlyRootFilesystem || len(c.SecurityContext.Capabilities.Drop) != 1 {
		t.Fatal("connector workload is not gated and Restricted")
	}
	for _, s := range spec.Volumes[0].Projected.Sources {
		if s.Secret != nil {
			t.Fatal("connector workload mounts a Secret")
		}
	}
	cluster, role := regionalRBAC("region")
	for _, r := range append(cluster.Rules, role.Rules...) {
		for _, resource := range r.Resources {
			if resource == "secrets" && (len(r.ResourceNames) != 1 || r.ResourceNames[0] != RegionalSecret) {
				t.Fatal("Secret access beyond the credential Secret")
			}
		}
	}
	now := time.Now()
	envelope := value.BootstrapEnvelope{BootstrapID: ownerID(4), Binding: value.PeerBinding{InstallationID: offer.InstallationID, ClusterID: ownerID(5), PeerID: ownerID(6), IssuerEpoch: offer.IssuerEpoch, Role: value.ConnectorPeer},
		DeliveryProfile: "regional-installer", RequestDigest: artifact.Digest{1}, NotBefore: now, NotAfter: now.Add(5 * time.Minute), Secret: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	plan := RegionalInstallPlan{Offer: offer, Bootstrap: envelope, Namespace: "asservat-connector"}
	if !plan.valid() {
		t.Fatal("matching plan refused")
	}
	other := plan
	other.Bootstrap.Binding.IssuerEpoch = ownerID(9)
	if other.valid() {
		t.Fatal("bootstrap for another issuer epoch accepted")
	}
	other = plan
	other.Namespace = "kube-system"
	if other.valid() {
		t.Fatal("system namespace accepted")
	}
	// ADR-196 decision 7: an executor offer requires the evidence credential
	// and a digest-pinned image; a partial offer or a stray credential fails.
	executor := plan
	executor.Offer.Image = "registry.invalid/asservat@sha256:" + strings.Repeat("ab", 32)
	executor.Offer.Owners, executor.Offer.KeyService = &contracts.RegionalContextOwners{}, &contracts.RegionalWrapService{KeyID: "artifact"}
	executor.Offer.WorkKey, executor.Offer.EvidenceStore = &contracts.APIContextWorkPublicKey{ID: "work-v1"}, &contracts.RegionalEvidenceStore{StoreID: ownerID(7)}
	if executor.valid() {
		t.Fatal("executor offer accepted without the evidence credential")
	}
	executor.Evidence = []byte(`{"accessKeyID":"synthetic","secretAccessKey":"synthetic-secret","sessionToken":""}`)
	if executor.valid() {
		t.Fatal("executor accepted without separate history capability")
	}
	executor.History = []byte(`{"accessKeyID":"synthetic-history","secretAccessKey":"synthetic-history-secret","sessionToken":""}`)
	if !executor.valid() {
		t.Fatal("complete executor plan refused")
	}
	partial := executor
	partial.Offer.WorkKey = nil
	if partial.valid() {
		t.Fatal("partial executor offer accepted")
	}
	stray := plan
	stray.Evidence = executor.Evidence
	if stray.valid() {
		t.Fatal("evidence credential accepted without an executor offer")
	}
	// ADR-231: the optional Alertmanager URL belongs to an executor and
	// carries no credential.
	alerts := executor
	alerts.Alertmanager = "http://alertmanager-operated.monitoring.svc:9093"
	if !alerts.valid() {
		t.Fatal("executor plan with an Alertmanager refused")
	}
	alerts.Alertmanager = "http://user:secret@alertmanager:9093"
	if alerts.valid() {
		t.Fatal("Alertmanager URL with credentials accepted")
	}
	stray.Evidence, stray.Alertmanager = nil, "http://alertmanager-operated.monitoring.svc:9093"
	if stray.valid() {
		t.Fatal("Alertmanager accepted without an executor offer")
	}
	mounted := 0
	for _, s := range RegionalWorkload(executor.Offer, true, false).Spec.Template.Spec.Volumes[0].Projected.Sources {
		if s.Secret != nil {
			if s.Secret.Name != RegionalEvidence || len(s.Secret.Items) != 2 || s.Secret.Items[0].Path != "evidence-storage.json" || s.Secret.Items[1].Path != contracts.RegionalHistoryCredentialFile {
				t.Fatal("executor mounts another Secret", s.Secret.Name)
			}
			mounted++
		}
	}
	if mounted != 1 {
		t.Fatal("executor does not mount its evidence credential")
	}
	_, connectorRules, capacity := regionalExecutorRBAC("region")
	for _, r := range append(connectorRules, capacity.Rules...) {
		for _, resource := range r.Resources {
			if resource == "secrets" && (len(r.ResourceNames) != 1 || r.ResourceNames[0] != RegionalEvidence || len(r.Verbs) != 1 || r.Verbs[0] != "get") {
				t.Fatal("executor Secret access beyond reading its evidence credential", r)
			}
		}
	}
}

// Installer failures name the step path and a closed cause only.
func TestRegionalInstallErrorRendering(t *testing.T) {
	nested := &regionalInstallError{step: "protection-proof", cause: &regionalInstallError{step: "source", cause: cfg.ErrUnavailable}}
	if got := nested.Error(); got != "regional installation stopped at protection-proof/source: unavailable" || !errors.Is(nested, cfg.ErrUnavailable) {
		t.Fatal("nested step text", got)
	}
	api := &regionalInstallError{step: "deployment", cause: &regionalAPIError{reason: "Forbidden"}}
	if api.Error() != "regional installation stopped at deployment: API Forbidden" {
		t.Fatal("API reason text", api.Error())
	}
}
