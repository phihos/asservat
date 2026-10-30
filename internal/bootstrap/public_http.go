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
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
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
	// ADR-190: the normal and resolution lanes read their current accepted
	// profile before each new Begin; each policy gets its own auditor.
	digest, ok := publicDigest(p.Capacity.QualificationDigest)
	if !ok {
		return nil, &fixedStepError{"qualification", mounts.ErrUnavailable}
	}
	profilePool, err := d.public.open(ctx, "capacity-profile-read")
	if err != nil {
		return nil, &fixedStepError{"profiles", err}
	}
	profiles, err := postgres.NewCapacityAuditProfiles(ctx, profilePool, root, installation, p.Capacity.QualificationID, digest, p.Capacity.AccountVersion)
	if err != nil {
		return nil, &fixedStepError{"profiles", mounts.ErrUnavailable}
	}
	auditor := func(lane string) (*auditapp.SelectedOperationAuditor, error) {
		journalPool, err := d.public.open(ctx, "audit-"+lane+"-journal")
		if err != nil {
			return nil, err
		}
		ackPool, err := d.public.open(ctx, "audit-"+lane+"-ack")
		if err != nil {
			return nil, err
		}
		recovery := d.shared.guards.Recovery
		return auditapp.NewSelectedOperationAuditor(lane, profiles, func(call context.Context, policy audit.OperationLifecyclePolicy) (*auditapp.HealthyOperationAuditor, error) {
			if policy.Lane != lane || policy.RootID != root || policy.InstallationID != installation {
				return nil, mounts.ErrUnavailable
			}
			journal, err := postgres.NewHealthyOperationJournal(call, journalPool, policy, recovery)
			if err != nil {
				return nil, mounts.ErrUnavailable
			}
			acks, err := postgres.NewOperationAcknowledgements(call, ackPool, root, lane, recovery)
			if err != nil {
				return nil, mounts.ErrUnavailable
			}
			lifecycle, err := postgres.NewOperationLifecycles(call, journalPool, root, lane, recovery)
			if err != nil {
				return nil, mounts.ErrUnavailable
			}
			objects, closed, err := a.operationObjects(policy.StoreID)
			if err != nil {
				return nil, mounts.ErrUnavailable
			}
			return auditapp.NewHealthyOperationAuditor(policy, journal, acks, objects, closed, lifecycle, time.Now)
		})
	}
	normal, err := auditor("normal")
	if err != nil {
		return nil, &fixedStepError{"audit-normal", mounts.ErrUnavailable}
	}
	resolution, err := auditor("resolution")
	if err != nil {
		return nil, &fixedStepError{"audit-resolution", mounts.ErrUnavailable}
	}

	// ADR-249: the protected identity settings carry the approval settings
	// (step-up and the installation's recording-approval switch).
	pc.investigation.Approvals = id.mcp.Policies
	operations, err := NewPublicContextOperations(PublicContextOperationsConfig{RootID: root, InstallationID: installation, PublicOrigin: p.Origin, CollectionEnabled: true, Now: time.Now, NewID: ownerRandomID},
		PublicContextOperationServices{Recordings: pc.recordings, Cancellations: pc.cancellations, History: pc.history, Investigation: pc.investigation, Intents: pc.intents, Regional: pc.regional, Progress: pc.progress, Cases: pc.cases, Downloads: dl.coordinator, Native: dl.native, Projection: dl.projection})
	if err != nil {
		return nil, &fixedStepError{"operations", mounts.ErrUnavailable}
	}
	// ADR-228: activate_policy and get_policy_status on the same audited
	// routes, and the restart trigger that RunPublic supervises.
	policies, trigger, err := composePublicPolicies(PublicContextOperationsConfig{RootID: root, InstallationID: installation, PublicOrigin: p.Origin, CollectionEnabled: true, Now: time.Now, NewID: ownerRandomID},
		PublicContextOperationServices{History: pc.history, Investigation: pc.investigation, Intents: pc.intents, Regional: pc.regional, Progress: pc.progress, Cases: pc.cases, Downloads: dl.coordinator, Native: dl.native, Projection: dl.projection}, pc)
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
	shares, err := composePublicShares(PublicContextOperationsConfig{RootID: root, InstallationID: installation, PublicOrigin: p.Origin, CollectionEnabled: true, Now: time.Now, NewID: ownerRandomID},
		PublicContextOperationServices{History: pc.history, Investigation: pc.investigation, Intents: pc.intents, Regional: pc.regional, Progress: pc.progress, Cases: pc.cases, Downloads: dl.coordinator, Native: dl.native, Projection: dl.projection}, pc)
	if err != nil {
		return nil, &fixedStepError{"shares", mounts.ErrUnavailable}
	}
	if operations, err = presentation.NewInvestigationShareOperations(operations, shares); err != nil {
		return nil, &fixedStepError{"shares", mounts.ErrUnavailable}
	}
	// ADR-234: caller-only explain_access on the same routes.
	access, err := composePublicAccess(PublicContextOperationsConfig{RootID: root, InstallationID: installation, PublicOrigin: p.Origin, CollectionEnabled: true, Now: time.Now, NewID: ownerRandomID},
		PublicContextOperationServices{History: pc.history, Investigation: pc.investigation, Intents: pc.intents, Regional: pc.regional, Progress: pc.progress, Cases: pc.cases, Downloads: dl.coordinator, Native: dl.native, Projection: dl.projection}, pc)
	if err != nil {
		return nil, &fixedStepError{"access", mounts.ErrUnavailable}
	}
	if operations, err = presentation.NewInvestigationAccessOperations(operations, access); err != nil {
		return nil, &fixedStepError{"access", mounts.ErrUnavailable}
	}
	// ADR-237: the fleet operators' browser-only preview_access_change.
	preview, err := composePublicAccessPreview(PublicContextOperationsConfig{RootID: root, InstallationID: installation, PublicOrigin: p.Origin, CollectionEnabled: true, Now: time.Now, NewID: ownerRandomID},
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
	retentionPreview, err := composePublicRetentionPreview(PublicContextOperationsConfig{RootID: root, InstallationID: installation, PublicOrigin: p.Origin, CollectionEnabled: true, Now: time.Now, NewID: ownerRandomID},
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
	o := p.OperationAudit
	services := PublicContextServices{Sessions: id.sessions, MCPIdentity: id.mcp, DownloadIdentity: id.download, Operations: operations, NormalAudit: normal, ResolutionAudit: resolution, AuditMAC: pc.mac, Native: dl.native.Runtime, Transfer: dl.native.Transfer}
	if pc.fleet != nil {
		services.Fleet = pc.fleet
	}
	// ADR-210: the privacy operator's processing changes on the normal lane.
	if pc.processingPolicy != nil {
		pool, err := d.public.open(ctx, "processing-decision")
		if err != nil {
			return nil, &fixedStepError{"processing-sql", err}
		}
		decisions, err := postgres.NewProcessingDecisions(ctx, pool, root, d.shared.guards.Recovery)
		if err != nil {
			return nil, &fixedStepError{"processing-sql", mounts.ErrUnavailable}
		}
		services.Processing = publicProcessingChanges{root: root, installation: installation, profiles: profiles, policies: pc.processingPolicy, recovery: pc.recovery, decisions: decisions, audit: normal, mac: pc.mac, refused: eventLog(os.Stderr, "processing change refused")}
	}
	h, err := NewPublicContextHandler(PublicContextConfig{PublicOrigin: p.Origin, Issuer: id.settings.Issuer, Version: p.Version,
		OperationConcurrency: p.OperationConcurrency, MCPPerIdentity: p.MCPPerIdentity, DownloadConcurrency: p.DownloadConcurrency, DownloadsPerIdentity: p.DownloadsPerIdentity, DownloadMaxDuration: time.Duration(p.DownloadMaxSeconds) * time.Second,
		Audit: presentation.AuditedOperationsConfig{RootID: root, Retention: time.Duration(o.RetentionSeconds) * time.Second, NormalConcurrency: o.NormalConcurrency, ResolutionConcurrency: o.ResolutionConcurrency, PerPrincipalConcurrency: o.PerPrincipalConcurrency, NormalPerSecond: o.NormalPerSecond, ResolutionPerSecond: o.ResolutionPerSecond, Now: time.Now, NewID: ownerRandomID}},
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
