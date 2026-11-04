package integration

import (
	"context"
	"crypto/tls"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Run on its own pristine service fixture. The existing shared lifecycle
// supplies controlled Pod/token/issuer facts, but audit, enrollment, certificate
// activation, native claim/binding and all six key consumptions use real SQL.
func TestSharedProfileComparisonLifecycleWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		t.Run("profile-comparison-native-key-authority", func(t *testing.T) {
			withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, qualifySharedProjectionLifecycle, true, true)
		})
	})
}

// Exercise the production SQL source constructor before the ledger fixture's
// explicitly synthetic C14 worker and native-operation rows. Publication,
// source verification, current C3 and the paid invocation are real fixture
// operations; this does not qualify worker enrollment, TLS or key consumption.
func qualifyProfileComparisonNativeSources(t *testing.T, f *queryLedgerFixture, ledger *postgres.ContextQueries, q value.ContextQuery, r value.ContextQueryRequest, current func() value.ContextProjectionAuthority) {
	t.Helper()
	operations, err := postgres.NewProjectionNativeOperations(ledger)
	if err != nil {
		t.Fatal("production comparison native adapter", err)
	}
	a := current()
	sources, err := operations.ReadProjectionComparisonSources(f.base.ctx, q, a, r)
	if err != nil {
		var step string
		if failure, ok := err.(interface{ FixedStep() string }); ok {
			step = failure.FixedStep()
		}
		t.Fatal("production paired SQL source constructor", step, err)
	}
	if !evidence.ProjectionComparisonSourcesMatch(sources, q.Scope, a) {
		t.Fatal("SQL source constructor returned incompatible labels or authority")
	}
	baseline, ok := q.Scope.BaselineScope()
	if !ok {
		t.Fatal("comparison baseline scope unavailable")
	}
	incident, ok := q.Scope.IncidentScope()
	if !ok {
		t.Fatal("comparison incident scope unavailable")
	}
	for ordinal, scope := range [2]value.ContextProjectionScope{baseline, incident} {
		source := sources[ordinal]
		if source.Expectation.NativeType != artifact.PprofArtifact || source.Expectation.Profile == nil || source.Expectation.CaseID != scope.CaseID || source.Expectation.CaptureUID != scope.CaptureID || source.Expectation.Registration.Location.ArtifactID != scope.ArtifactID || evidence.ContextCopiesDigest(source.Copies) != scope.Version || !reflect.DeepEqual(source.Expectation, f.published.Expectation) || source.Copies != f.published.Copies || !evidence.CanonicalProjectionExpectationBound(source) {
			t.Fatal("paired SQL source lost complete published expectation/copies", ordinal)
		}
	}
	if _, err = operations.ReadProjectionSource(f.base.ctx, q, a, r); err == nil {
		t.Fatal("legacy source API accepted a compound query")
	}
	// Both reads must consume the original compound current fence. A valid
	// shape with a changed baseline processing proof cannot disclose either
	// source, even when both labels refer to the same published artifact.
	changed := a
	child := *a.Baseline
	changed.Baseline = &child
	child.Environment.Processing.StateDigest[0]++
	if !changed.Valid(time.Now()) {
		t.Fatal("baseline current-fence negative is not a valid authority shape")
	}
	refused, err := operations.ReadProjectionComparisonSources(f.base.ctx, q, changed, r)
	if err == nil || refused[0].Expectation.CaptureUID != "" || refused[1].Expectation.CaptureUID != "" {
		t.Fatal("changed baseline current proof returned either native source", err)
	}
	t.Log("real comparison SQL source adapter: two complete same-artifact labels; compound-only API and baseline current fence; C14 enrollment/native key binding remain separate")
}
