package bootstrap

import (
	"io/fs"
	"net/http"
	"os"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/console"
	"asservat.local/asservat/internal/transport/browser"
	"asservat.local/asservat/internal/transport/mcp"
	"asservat.local/asservat/internal/transport/presentation"
)

// PublicContextConfig is an accepted installation input, never an HTTP body.
// It adds no collection enablement: only already composed operations exist.
type PublicContextConfig struct {
	PublicOrigin, Issuer, Version             string
	OperationConcurrency, MCPPerIdentity      int
	DownloadConcurrency, DownloadsPerIdentity int
	DownloadMaxDuration                       time.Duration
	Audit                                     presentation.AuditedOperationsConfig
}

// PublicContextServices are concrete role-composition dependencies. Bootstrap
// must supply protected providers and purpose-specific SQL/key credentials;
// this struct is not a configuration parser or a grant of authority. In
// particular, the two bearer resolvers have separately pinned resource audiences.
type PublicContextServices struct {
	Sessions                      *identities.BrowserSessions
	RefreshOwners                 *identities.BrowserRefreshOwners
	RefreshPauses                 identities.BrowserRefreshPauseReader
	MCPIdentity, DownloadIdentity identities.Resolver
	Operations                    *presentation.InvestigationOperations
	NormalAudit, ResolutionAudit  presentation.HealthyAuditGate
	AuditMAC                      *auditapp.OperationMAC
	Native                        *evidence.ContextNativeRuntime
	Transfer                      evidence.DownloadResponseTransfer
	// Fleet is the ADR-193 issuance route's service; nil leaves it absent.
	Fleet browser.FleetBootstrapService
	// Processing is the ADR-210 operator change service; nil leaves it absent.
	Processing browser.ProcessingChangeService
}

// NewPublicContextHandler composes the original HTTP handlers directly. It
// does not start a listener, observer, collector or refresh task. Their owning
// deployment must join them on shutdown before releasing its resources.
// The same healthy operation auditor is used across browser, MCP and content.
func NewPublicContextHandler(c PublicContextConfig, s PublicContextServices, files fs.FS) (http.Handler, error) {
	host, ok := publicContextHost(c.PublicOrigin)
	if !ok || s.Sessions == nil || s.Sessions.Issuer != c.Issuer || s.RefreshOwners == nil || s.RefreshPauses == nil || s.MCPIdentity == nil || s.DownloadIdentity == nil || s.Operations == nil || s.Operations.PublicOrigin() != c.PublicOrigin {
		return nil, &fixedStepError{"services", presentation.ErrOperationsConfiguration}
	}
	// No missing case or download service may be hidden behind an app-shell
	// fallback. Capture enablement remains the existing operation set's decision;
	// a deliberately disabled capture service may still expose retained evidence.
	for _, name := range []string{"list_diagnostics", "preview_capture", "get_capture", "resolve_capture_request", "get_case", "prepare_artifact_download", "get_artifact_download", "cancel_artifact_download"} {
		if _, available := s.Operations.Tool(name); !available {
			return nil, &fixedStepError{"tools", presentation.ErrOperationsConfiguration}
		}
	}
	static, e := console.New(c.PublicOrigin, files)
	if e != nil {
		return nil, &fixedStepError{"console", e}
	}
	audited, e := presentation.NewHealthyAuditedOperations(c.Audit, s.Operations, s.NormalAudit, s.ResolutionAudit, s.AuditMAC)
	if e != nil {
		return nil, &fixedStepError{"audited", e}
	}
	sessions := browser.SessionHandler{Origin: c.PublicOrigin, Issuer: c.Issuer, Sessions: s.Sessions}
	investigations, e := browser.NewAuditedDownloadInvestigationHandler(sessions, audited, s.RefreshOwners, c.OperationConcurrency)
	if e != nil {
		return nil, &fixedStepError{"investigations", e}
	}
	mcpHandler, e := mcp.NewAuditedContextHandler(mcp.Config{PublicOrigin: c.PublicOrigin, Issuer: c.Issuer, Version: c.Version, MaxConcurrent: c.OperationConcurrency, MaxPerIdentity: c.MCPPerIdentity}, s.MCPIdentity, audited)
	if e != nil {
		return nil, &fixedStepError{"mcp", e}
	}
	mcpHandler.Report = eventLog(os.Stderr, "mcp unavailable")
	audited.Timing = eventLog(os.Stderr, "mcp timing")
	// ADR-194 D1: a nil Native (no configured worker) serves no content; its
	// paths answer 503 rather than falling through to the console.
	var content http.Handler
	if s.Native != nil {
		if content, e = browser.NewDownloadContentHandler(browser.DownloadContentConfig{
			PublicOrigin: c.PublicOrigin, Issuer: c.Issuer,
			MaxConcurrent: c.DownloadConcurrency, MaxPerIdentity: c.DownloadsPerIdentity,
			MaxDuration: c.DownloadMaxDuration, Now: c.Audit.Now, NewID: c.Audit.NewID,
		}, sessions, s.DownloadIdentity, s.RefreshPauses, audited, s.Native, s.Transfer); e != nil {
			return nil, &fixedStepError{"downloads", e}
		}
	}
	var fleet http.Handler
	if s.Fleet != nil {
		if fleet, e = browser.NewFleetHandler(sessions, s.Fleet); e != nil {
			return nil, &fixedStepError{"fleet", e}
		}
	}
	var processing http.Handler
	if s.Processing != nil {
		if processing, e = browser.NewProcessingHandler(sessions, s.Processing); e != nil {
			return nil, &fixedStepError{"processing", e}
		}
	}
	return &publicContextRoutes{
		host: host, sessions: sessions, investigations: investigations, fleet: fleet, processing: processing,
		mcp: mcpHandler, content: content, console: static,
		mcpPath: mcp.Path, mcpMetadata: mcp.MetadataPath,
		contentPrefix:   browser.DownloadContentPrefix,
		contentMetadata: browser.DownloadContentMetadataPath,
	}, nil
}
