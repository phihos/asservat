package bootstrap

import (
	"os"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	executionapp "asservat.local/asservat/internal/application/execution"
	planningapp "asservat.local/asservat/internal/application/planning"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	catalogapp "asservat.local/asservat/internal/application/catalog"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/transport/presentation"
)

// These are accepted installation services, never decoded request input. This
// assembly opens no credential/listener and does not establish their authority.
// Protected deployment composition must verify original projections and supply
// current scoped adapters before calling it; no missing service gets a default.
type PublicContextOperationServices struct {
	Investigation captureapp.ContextInvestigation
	Intents       auditapp.CaptureOperationPublication
	Regional      RegionalAPIContextStart
	Progress      captureapp.ContextProgressService
	Cases         catalogapp.ContextCaseService
	Downloads     evidence.ContextDownloadCoordinator
	Native        ContextNativeDownloadServices
	Projection    *analysisapp.ContextProjectionService
}

type PublicContextOperationsConfig struct {
	RootID, InstallationID, PublicOrigin string
	CollectionEnabled                    bool
	Now                                  func() time.Time
	NewID                                func() string
}

type publicContextUseCases struct {
	submission captureapp.ContextSubmission
	progress   captureapp.ContextProgressService
	cases      catalogapp.ContextCaseService
	downloads  evidence.ContextDownloadCoordinator
	stop       evidence.ContextDownloadStopCoordinator
}

// NewPublicContextOperations constructs the one complete browser/MCP operation
// set. In particular request_capture uses ContextSubmission, including its
// explicit accepted-only Continue path, rather than admission without start.
// The same concrete native runtime owns preparation and active cancellation.
func NewPublicContextOperations(c PublicContextOperationsConfig, s PublicContextOperationServices) (*presentation.InvestigationOperations, error) {
	v, err := composePublicContextUseCases(c, s)
	if err != nil {
		return nil, err
	}
	// ADR-236: the progress SQL reader also reads capture history; "Collect
	// again" runs the same composed preview as a new request.
	var history presentation.ContextHistoryUseCase
	reader, readerOK := v.progress.Reader.(captureapp.ContextHistoryReader)
	workloads, workloadsOK := v.submission.Targets.(captureapp.RestartObserver)
	if readerOK && workloadsOK {
		history = captureapp.ContextHistoryService{RootID: c.RootID, InstallationID: c.InstallationID, Reader: reader, Targets: v.submission.Targets, Workloads: workloads, Previews: v.submission, Recovery: v.submission.Recovery, Now: c.Now}
	}
	captures, err := presentation.NewContextOperationsWithHistory(presentation.ContextOperationsConfig{PublicOrigin: c.PublicOrigin, CollectionEnabled: c.CollectionEnabled, Now: c.Now, NewID: c.NewID}, v.submission, v.progress, history)
	if err != nil {
		return nil, err
	}
	cases, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: c.PublicOrigin, Now: c.Now, NewID: c.NewID}, v.cases)
	if err != nil {
		return nil, err
	}
	downloads, err := presentation.NewContextDownloadOperations(presentation.ContextDownloadOperationsConfig{PublicOrigin: c.PublicOrigin, Now: c.Now, NewID: c.NewID}, v.downloads, v.stop)
	if err != nil {
		return nil, err
	}
	operations, err := presentation.NewInvestigationOperations(captures, cases, downloads)
	if err != nil || s.Projection == nil {
		return operations, err
	}
	q := s.Projection
	if q.Results.RootID != c.RootID || q.Results.InstallationID != c.InstallationID || !authorization.UUID(q.Results.HubProcessEpoch) || q.Results.Authority == nil || q.Results.Ledger == nil || q.Results.Reader == nil || q.Results.Now == nil || q.Results.NewID == nil || q.Recovery == nil || q.Routes == nil || q.Plans == nil || q.Workers == nil {
		return nil, presentation.ErrOperationsConfiguration
	}
	projection, err := presentation.NewContextProjectionOperations(*q, q.Results)
	if err != nil {
		return nil, err
	}
	return presentation.NewInvestigationProjectionOperations(operations, projection)
}

func composePublicContextUseCases(c PublicContextOperationsConfig, s PublicContextOperationServices) (publicContextUseCases, error) {
	var zero publicContextUseCases
	i, p, k, d, a := s.Investigation, s.Progress, s.Cases, s.Downloads, s.Intents
	if !authorization.UUID(c.RootID) || !authorization.UUID(c.InstallationID) || c.Now == nil || c.NewID == nil ||
		i.RootID != c.RootID || i.InstallationID != c.InstallationID || p.RootID != c.RootID || p.InstallationID != c.InstallationID ||
		k.RootID != c.RootID || k.InstallationID != c.InstallationID || d.RootID != c.RootID || d.InstallationID != c.InstallationID || a.RootID != c.RootID ||
		i.Previews == nil || i.Replay == nil || i.Admission == nil || i.Resolution == nil || i.Targets == nil || i.Eligibility == nil || i.Capabilities == nil || i.Retention == nil || i.Storage == nil || i.Processing == nil || i.Recovery == nil ||
		i.Lifetime < time.Second || i.Lifetime > 5*time.Minute || i.Lifetime%time.Microsecond != 0 ||
		a.Completed == nil || a.Journal == nil || a.Acknowledgements == nil || a.Writer == nil || a.Reader == nil || a.MAC == nil ||
		!regionalHubRunner(s.Regional.Runner) || s.Regional.Signer == nil || s.Regional.Router == nil ||
		p.Reader == nil || p.Navigation != nil || k.Routes == nil || k.Permissions == nil || k.Catalog == nil || k.Retention == nil || k.Processing == nil ||
		d.Routes == nil || d.Sources == nil || d.Authority == nil || d.Sessions == nil || d.Plans == nil || d.Runtime != nil ||
		s.Native.Runtime == nil && s.Native.Stop.Active != nil || s.Native.Runtime != nil && s.Native.Stop.Active != s.Native.Runtime || s.Native.Stop.Ledger == nil || s.Native.Stop.Acknowledgements == nil || s.Native.Stop.Objects == nil {
		return zero, presentation.ErrOperationsConfiguration
	}
	// Shared freshness functions and recovery source are fixed once at assembly;
	// this creates no observation and replaces no original request deadline.
	i.Now, i.NewID, a.Now = c.Now, c.NewID, c.Now
	s.Regional.Runner.Capabilities, s.Regional.Runner.Recovery, s.Regional.Runner.Now, s.Regional.Now = i.Capabilities, i.Recovery, c.Now, c.Now
	p.Recovery, p.Now = i.Recovery, c.Now
	k.Recovery, k.Now = i.Recovery, c.Now
	p.Navigation = captureapp.ContextCaseNavigator{Cases: k, Now: c.Now}
	d.Recovery, d.Now, d.NewID = i.Recovery, c.Now, c.NewID
	// ADR-194 D1: without a configured worker there is no native runtime and
	// prepare fails closed; a typed nil must not become a non-nil interface.
	if s.Native.Runtime != nil {
		d.Runtime = s.Native.Runtime
	}
	stop := s.Native.Stop
	stop.Now = c.Now
	return publicContextUseCases{captureapp.ContextSubmission{ContextInvestigation: i, Intents: a, Start: s.Regional}, p, k, d, stop}, nil
}

// regionalHubRunner accepts only the hub's SQL/authority ports (ADR-171):
// capability, recovery and clock come from the shared assembly, and every
// cluster-local port is bound per exchange, never configured here.
func regionalHubRunner(r executionapp.APIContextRunner) bool {
	return r.Read != nil && r.Prepare != nil && r.Record != nil && r.Eligibility != nil && r.Retention != nil &&
		r.Capabilities == nil && r.Recovery == nil && r.Now == nil &&
		r.Process == nil && r.Local == nil && r.Starts == nil && r.Targets == nil && r.Output == nil && r.Collector == nil
}

// composePublicPolicies composes the ADR-228 restart-trigger services onto
// the same investigation, recovery and clock as the public operations. The
// trigger reuses the composed submission unchanged: preview, admission,
// intent audit and regional start run exactly as for a human request.
func composePublicPolicies(c PublicContextOperationsConfig, s PublicContextOperationServices, pc *publicContext) (*presentation.PolicyOperations, *captureapp.PolicyTrigger, error) {
	v, err := composePublicContextUseCases(c, s)
	if err != nil || pc == nil || pc.policies == nil || pc.policyTriggers == nil || pc.automation == nil || pc.hubPolicies == nil || pc.permissions == nil {
		return nil, nil, presentation.ErrOperationsConfiguration
	}
	observer, ok := v.submission.Targets.(captureapp.RestartObserver)
	if !ok {
		return nil, nil, presentation.ErrOperationsConfiguration
	}
	activation := captureapp.PolicyActivation{RootID: c.RootID, InstallationID: c.InstallationID, RecipeName: planningapp.ContextRecipeName, RecipeDigest: planningapp.RecipeDigest(), Documents: pc.hubPolicies, Sources: pc.policies, Observer: observer, Ledger: pc.policyTriggers, Permissions: pc.permissions, Automation: pc.automation, Acceptor: pc.policies, Audit: pc.policyAudit, Recovery: v.submission.Recovery, Now: c.Now, Report: eventLog(os.Stderr, "policy activation refused")}
	status := captureapp.PolicyStatusService{RootID: c.RootID, InstallationID: c.InstallationID, Documents: pc.hubPolicies, Ledger: pc.policyTriggers, Permissions: pc.permissions, Recovery: v.submission.Recovery, Now: c.Now}
	deactivation := captureapp.PolicyDeactivation{RootID: c.RootID, InstallationID: c.InstallationID, Documents: pc.hubPolicies, Ledger: pc.policyTriggers, Permissions: pc.permissions, Recovery: v.submission.Recovery, Now: c.Now}
	operations, err := presentation.NewPolicyOperations(c.PublicOrigin, c.Now, c.NewID, activation, status, deactivation)
	if err != nil {
		return nil, nil, err
	}
	trigger := &captureapp.PolicyTrigger{RootID: c.RootID, InstallationID: c.InstallationID, RecipeName: planningapp.ContextRecipeName, RecipeDigest: planningapp.RecipeDigest(), Ledger: pc.policyTriggers, Documents: pc.hubPolicies, Sources: pc.policies, Accepted: pc.policies, Observer: observer, Capture: v.submission, Audit: pc.policyAudit, Now: c.Now, Report: timedEventLog(os.Stderr, "policy trigger")}
	return operations, trigger, nil
}

// composePublicShares composes the ADR-232 share operations on the same case
// routes, permissions, catalog, recovery and clock as get_case.
func composePublicShares(c PublicContextOperationsConfig, s PublicContextOperationServices, pc *publicContext) (*presentation.ShareOperations, error) {
	v, err := composePublicContextUseCases(c, s)
	if err != nil || pc == nil || pc.shares == nil || pc.caseRoutes == nil || pc.permissions == nil || pc.catalog == nil {
		return nil, presentation.ErrOperationsConfiguration
	}
	service := sharing.Service{RootID: c.RootID, InstallationID: c.InstallationID, Routes: pc.caseRoutes, Permissions: pc.permissions, Catalog: pc.catalog, Store: pc.shares, Recovery: v.submission.Recovery, NewID: c.NewID, Now: c.Now}
	return presentation.NewShareOperations(c.PublicOrigin, c.Now, c.NewID, service)
}

// composePublicAccess composes the ADR-234 caller-only explain_access
// operation on the same target resolution, permission projection, recovery
// and clock as preview_capture and get_case.
func composePublicAccess(c PublicContextOperationsConfig, s PublicContextOperationServices, pc *publicContext) (*presentation.AccessOperations, error) {
	v, err := composePublicContextUseCases(c, s)
	if err != nil || pc == nil || pc.permissions == nil {
		return nil, presentation.ErrOperationsConfiguration
	}
	service := authapp.AccessExplainer{InstallationID: c.InstallationID, Targets: v.submission.Targets, Permissions: pc.permissions, Recovery: v.submission.Recovery, Now: c.Now}
	return presentation.NewAccessOperations(c.PublicOrigin, c.Now, c.NewID, service)
}
