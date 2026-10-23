package bootstrap

import (
	"errors"
	"slices"
	"testing"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	"asservat.local/asservat/internal/transport/presentation"
)

// Constructor-only ports panic if invoked: composing tools is not an authority
// observation, query admission, worker creation or a native download operation.
type publicProjectionPorts struct {
	analysisapp.CurrentContextProjectionAuthority
	analysisapp.ContextQueryLedger
	analysisapp.ContextProjectionReader
	analysisapp.ContextProjectionRecovery
	analysisapp.ContextProjectionRoutes
	analysisapp.ContextQueryPlans
	analysisapp.ContextProjectionWorkerAdmission
}

func publicProjectionFixture(c PublicContextOperationsConfig) *analysisapp.ContextProjectionService {
	p := &publicProjectionPorts{}
	return &analysisapp.ContextProjectionService{
		Results:  analysisapp.ContextProjectionResults{RootID: c.RootID, InstallationID: c.InstallationID, HubProcessEpoch: c.NewID(), Authority: p, Ledger: p, Reader: p, Now: c.Now, NewID: c.NewID},
		Recovery: p, Routes: p, Plans: p, Workers: p,
	}
}
func TestPublicContextProjectionRegistersOnlyCompleteInstalledComposition(t *testing.T) {
	c, services := publicContextOperationFixture(t)
	base, err := NewPublicContextOperations(c, services)
	if err != nil {
		t.Fatal(err)
	}
	services.Projection = publicProjectionFixture(c)
	composed, err := NewPublicContextOperations(c, services)
	if err != nil {
		t.Fatal(err)
	}
	want := append(base.ToolNames(), "get_file_excerpt", "get_query_result")
	slices.Sort(want)
	if !slices.Equal(composed.ToolNames(), want) {
		t.Fatal("query or unrelated tools missing", composed.ToolNames())
	}
	for _, name := range []string{"get_file_excerpt", "get_query_result"} {
		if presentation.BrowserOperationSupported(base, name) || !presentation.BrowserOperationSupported(composed, name) {
			t.Fatal("optional browser composition", name)
		}
	}
	// Disabling new captures does not disable ordinary reads of saved content.
	c.CollectionEnabled = false
	composed, err = NewPublicContextOperations(c, services)
	if err != nil || !presentation.BrowserOperationSupported(composed, "get_file_excerpt") || slices.Contains(composed.ToolNames(), "request_capture") {
		t.Fatal("read tied to collection enablement", err)
	}
}
func TestPublicContextProjectionRejectsPartialOrForeignServices(t *testing.T) {
	for name, mutate := range map[string]func(*analysisapp.ContextProjectionService){
		"root": func(s *analysisapp.ContextProjectionService) {
			s.Results.RootID = "10000000-0000-4000-8000-000000000099"
		},
		"installation": func(s *analysisapp.ContextProjectionService) {
			s.Results.InstallationID = "10000000-0000-4000-8000-000000000099"
		},
		"process":   func(s *analysisapp.ContextProjectionService) { s.Results.HubProcessEpoch = "" },
		"authority": func(s *analysisapp.ContextProjectionService) { s.Results.Authority = nil },
		"ledger":    func(s *analysisapp.ContextProjectionService) { s.Results.Ledger = nil },
		"reader":    func(s *analysisapp.ContextProjectionService) { s.Results.Reader = nil },
		"clock":     func(s *analysisapp.ContextProjectionService) { s.Results.Now = nil },
		"id":        func(s *analysisapp.ContextProjectionService) { s.Results.NewID = nil },
		"recovery":  func(s *analysisapp.ContextProjectionService) { s.Recovery = nil },
		"routes":    func(s *analysisapp.ContextProjectionService) { s.Routes = nil },
		"plans":     func(s *analysisapp.ContextProjectionService) { s.Plans = nil },
		"workers":   func(s *analysisapp.ContextProjectionService) { s.Workers = nil },
	} {
		t.Run(name, func(t *testing.T) {
			c, services := publicContextOperationFixture(t)
			services.Projection = publicProjectionFixture(c)
			mutate(services.Projection)
			if got, err := NewPublicContextOperations(c, services); got != nil || !errors.Is(err, presentation.ErrOperationsConfiguration) {
				t.Fatal("incomplete public projection enabled", err)
			}
		})
	}
}
