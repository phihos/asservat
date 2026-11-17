package bootstrap

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/transport/presentation"
)

// newPublicHandler is the ADR-180 P5 assembly: both audited operation lanes,
// the complete operation set and the HTTP routes.
func newPublicHandler(ctx context.Context, d *OwnerDeployment, a publicAuditStore) (http.Handler, error) {
	in, id, pc, dl := d.inputs, d.publicID, d.publicContext, d.publicDownloads
	c, p := in.config, in.config.Public
	root, installation := c.PermissionRootID, c.InstallationID
	if p == nil || id == nil || pc == nil || dl == nil || d.Runtime == nil {
		return nil, &fixedStepError{"inputs", mounts.ErrUnavailable}
	}
	auditPool, err := d.public.open(ctx, "audit")
	if err != nil {
		return nil, &fixedStepError{"audit", err}
	}
	recorder, err := postgres.NewAuditEvents(auditPool)
	if err != nil {
		return nil, &fixedStepError{"audit", err}
	}

	// ADR-335 D14: identity.administrators names the installation administrators.
	pc.administrators = id.mcp.Policies
	ongoingSources := pc.packetSourceRuntime(time.Now, ownerRandomID)
	clusterNames := map[string]string{}
	if !in.hubOnly() {
		clusterNames[presentation.LocalClusterName] = c.ClusterID
	}
	for _, r := range in.remote {
		clusterNames[r.Name] = r.clusterID
	}
	clusters := presentation.NewClusterNames(clusterNames)
	operations, err := NewPublicContextOperations(PublicContextOperationsConfig{RootID: root, InstallationID: installation, PublicOrigin: p.Origin, CollectionEnabled: true, Now: time.Now, NewID: ownerRandomID, Clusters: clusters},
		PublicContextOperationServices{ongoingSources: ongoingSources, Recordings: pc.recordings, Cancellations: pc.cancellations, History: pc.history, Investigation: pc.investigation, Intents: pc.intents, Regional: pc.regional, Progress: pc.progress, Cases: pc.cases, Downloads: dl.coordinator, Native: dl.native, Projection: dl.projection})
	if err != nil {
		return nil, &fixedStepError{"operations", mounts.ErrUnavailable}
	}
	liveService, err := d.newPublicLive(ctx)
	if err != nil {
		return nil, &fixedStepError{"live", err}
	}
	if liveService != nil {
		liveOperations, e := presentation.NewLiveOperations(p.Origin, liveService, time.Now)
		if e != nil {
			return nil, e
		}
		liveOperations.Diagnose = eventLog(os.Stderr, "live operation refused")
		operations, e = presentation.NewInvestigationLiveOperations(operations, liveOperations)
		if e != nil {
			return nil, e
		}
	}
	// ADR-228: activate_policy and get_policy_status on the same audited
	// routes, and the restart trigger that RunPublic supervises.
	policies, trigger, err := composePublicPolicies(PublicContextOperationsConfig{RootID: root, InstallationID: installation, PublicOrigin: p.Origin, CollectionEnabled: true, Now: time.Now, NewID: ownerRandomID, Clusters: clusters},
		PublicContextOperationServices{ongoingSources: ongoingSources, History: pc.history, Investigation: pc.investigation, Intents: pc.intents, Regional: pc.regional, Progress: pc.progress, Cases: pc.cases, Downloads: dl.coordinator, Native: dl.native, Projection: dl.projection}, pc)
	if err != nil {
		return nil, &fixedStepError{"policies", mounts.ErrUnavailable}
	}
	if operations, err = presentation.NewInvestigationPolicyOperations(operations, policies); err != nil {
		return nil, &fixedStepError{"policies", mounts.ErrUnavailable}
	}
	d.policyTrigger = trigger
	collect := pc.collect
	d.recordingCollect = &collect
	d.history = pc.history
	// ADR-232: create_share, list_shares and revoke_share on the same routes.
	shares, err := composePublicShares(PublicContextOperationsConfig{RootID: root, InstallationID: installation, PublicOrigin: p.Origin, CollectionEnabled: true, Now: time.Now, NewID: ownerRandomID, Clusters: clusters},
		PublicContextOperationServices{History: pc.history, Investigation: pc.investigation, Intents: pc.intents, Regional: pc.regional, Progress: pc.progress, Cases: pc.cases, Downloads: dl.coordinator, Native: dl.native, Projection: dl.projection}, pc)
	if err != nil {
		return nil, &fixedStepError{"shares", mounts.ErrUnavailable}
	}
	if operations, err = presentation.NewInvestigationShareOperations(operations, shares); err != nil {
		return nil, &fixedStepError{"shares", mounts.ErrUnavailable}
	}
	// ADR-234: caller-only explain_access on the same routes.
	access, err := composePublicAccess(PublicContextOperationsConfig{RootID: root, InstallationID: installation, PublicOrigin: p.Origin, CollectionEnabled: true, Now: time.Now, NewID: ownerRandomID, Clusters: clusters},
		PublicContextOperationServices{History: pc.history, Investigation: pc.investigation, Intents: pc.intents, Regional: pc.regional, Progress: pc.progress, Cases: pc.cases, Downloads: dl.coordinator, Native: dl.native, Projection: dl.projection}, pc)
	if err != nil {
		return nil, &fixedStepError{"access", mounts.ErrUnavailable}
	}
	if operations, err = presentation.NewInvestigationAccessOperations(operations, access); err != nil {
		return nil, &fixedStepError{"access", mounts.ErrUnavailable}
	}
	// ADR-237: the fleet operators' browser-only preview_access_change.
	preview, err := composePublicAccessPreview(PublicContextOperationsConfig{RootID: root, InstallationID: installation, PublicOrigin: p.Origin, CollectionEnabled: true, Now: time.Now, NewID: ownerRandomID, Clusters: clusters},
		PublicContextOperationServices{History: pc.history, Investigation: pc.investigation, Intents: pc.intents, Regional: pc.regional, Progress: pc.progress, Cases: pc.cases, Downloads: dl.coordinator, Native: dl.native, Projection: dl.projection}, pc)
	if err != nil {
		return nil, &fixedStepError{"access-preview", mounts.ErrUnavailable}
	}
	if preview != nil {
		if operations, err = presentation.NewInvestigationAccessPreviewOperations(operations, preview); err != nil {
			return nil, &fixedStepError{"access-preview", mounts.ErrUnavailable}
		}
	}
	// ADR-240: the fleet operators' browser-only preview_retention_change.
	retentionPreview, err := composePublicRetentionPreview(PublicContextOperationsConfig{RootID: root, InstallationID: installation, PublicOrigin: p.Origin, CollectionEnabled: true, Now: time.Now, NewID: ownerRandomID, Clusters: clusters},
		PublicContextOperationServices{History: pc.history, Investigation: pc.investigation, Intents: pc.intents, Regional: pc.regional, Progress: pc.progress, Cases: pc.cases, Downloads: dl.coordinator, Native: dl.native, Projection: dl.projection}, pc)
	if err != nil {
		return nil, &fixedStepError{"retention-preview", mounts.ErrUnavailable}
	}
	if retentionPreview != nil {
		if operations, err = presentation.NewInvestigationRetentionPreviewOperations(operations, retentionPreview); err != nil {
			return nil, &fixedStepError{"retention-preview", mounts.ErrUnavailable}
		}
	}
	// ADR-249: get_grant and the approval inbox on the same audited routes.
	grantOperations, err := presentation.NewGrantOperations(p.Origin, time.Now, ownerRandomID, pc.grants)
	if err != nil {
		return nil, &fixedStepError{"grants", mounts.ErrUnavailable}
	}
	if operations, err = presentation.NewInvestigationGrantOperations(operations, grantOperations); err != nil {
		return nil, &fixedStepError{"grants", mounts.ErrUnavailable}
	}
	services := PublicContextServices{Sessions: id.sessions, MCPIdentity: id.mcp, DownloadIdentity: id.download, Operations: operations, Audit: recorder, AuditMAC: pc.mac, Native: dl.native.Runtime, Transfer: dl.native.Transfer}
	// ADR-210: privacy changes write their audit row with the decision.
	if pc.processingPolicy != nil {
		pool, err := d.public.open(ctx, "processing-decision")
		if err != nil {
			return nil, &fixedStepError{"processing-sql", err}
		}
		decisions, err := postgres.NewProcessingDecisions(ctx, pool, root)
		if err != nil {
			return nil, &fixedStepError{"processing-sql", mounts.ErrUnavailable}
		}
		inventory, err := postgres.NewProcessingInventory(ctx, pool, root)
		if err != nil {
			return nil, &fixedStepError{"processing-inventory", mounts.ErrUnavailable}
		}
		services.ProcessingRules = publicProcessingInventory{privacyapp.ProcessingRuleInventory{RootID: root, InstallationID: installation, Policies: pc.processingPolicy, Inventory: inventory, Now: time.Now}}
		discovery, err := presentation.NewProcessingDiscoveryOperations(p.Origin, time.Now, ownerRandomID, clusters,
			privacyapp.ProcessingEvidenceDiscovery{RootID: root, InstallationID: installation, Policies: pc.processingPolicy, Discovery: inventory, Now: time.Now},
			&privacyapp.ProcessingErasureStatus{RootID: root, InstallationID: installation, Policies: pc.processingPolicy, Status: decisions, Now: time.Now},
			&privacyapp.ProcessingReport{RootID: root, InstallationID: installation, Policies: pc.processingPolicy, Reports: inventory, Now: time.Now})
		if err != nil {
			return nil, &fixedStepError{"processing-discovery", err}
		}
		if services.Operations, err = presentation.NewInvestigationProcessingDiscoveryOperations(operations, discovery); err != nil {
			return nil, &fixedStepError{"processing-discovery", err}
		}
		services.Processing = publicProcessingChanges{root: root, installation: installation, policies: pc.processingPolicy, decisions: decisions, artifactScopes: inventory, refused: eventLog(os.Stderr, "processing change refused")}
	}
	// One LISTEN connection feeds every console status stream (REQ-INT-003).
	progressPool, err := d.public.open(ctx, "hub-metadata-read")
	if err != nil {
		return nil, &fixedStepError{"capture-progress-pool", mounts.ErrUnavailable}
	}
	services.CaptureChanges = presentation.NewChanges()
	postgres.ListenPayloads(ctx, progressPool, postgres.CaptureProgressChannel, services.CaptureChanges.Publish)
	h, err := NewPublicContextHandler(PublicContextConfig{PublicOrigin: p.Origin, Issuer: id.settings.Issuer, Version: p.Version,
		OperationConcurrency: p.OperationConcurrency, MCPPerIdentity: p.MCPPerIdentity, DownloadConcurrency: p.DownloadConcurrency,
		Audit: presentation.AuditedOperationsConfig{RootID: root, Now: time.Now, NewID: ownerRandomID, Changes: services.CaptureChanges}},
		services, os.DirFS(contracts.OwnerPublicConsoleRoot))
	if err != nil {
		return nil, &fixedStepError{"handler", err}
	}
	return h, nil
}

// publicCertificate serves the mounted public TLS pair and reloads it when the
// mounted files change; a failed reload keeps no stale pair beyond the files.
type publicCertificate struct {
	inputs *providerInputs
	mu     sync.Mutex
	cert   *tls.Certificate
	raw    []byte
}

func (c *publicCertificate) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	crt, err := c.inputs.read(ctx, contracts.OwnerPublicTLSCertificate, 64<<10)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert != nil && string(crt) == string(c.raw) {
		return c.cert, nil
	}
	key, err := c.inputs.read(ctx, contracts.OwnerPublicTLSKey, 64<<10)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	c.cert, c.raw = &pair, crt
	return c.cert, nil
}

// publicTLS is HTTP/2-capable TLS 1.3 for browsers and MCP clients.
func publicTLS(in *providerInputs) *tls.Config {
	c := &publicCertificate{inputs: in}
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: c.get, NextProtos: []string{"h2", "http/1.1"}}
}
