package privacy

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

type processingReportReadFunc func(context.Context, value.ProcessingAuthority, value.ProcessingReportQuery) (value.ProcessingReportPage, error)

func (f processingReportReadFunc) ReadProcessingReport(ctx context.Context, a value.ProcessingAuthority, q value.ProcessingReportQuery) (value.ProcessingReportPage, error) {
	return f(ctx, a, q)
}

func TestProcessingReportPreservesOperatorSourceAndOriginalBounds(t *testing.T) {
	for _, name := range []string{"allowed", "invalid-section", "ordinary-reader", "unavailable", "wrong-root", "wrong-policy", "wrong-selection", "post-read-role-loss", "post-read-expiry"} {
		t.Run(name, func(t *testing.T) {
			fixture, changes, _ := newProcessingFixture(t)
			query := value.ProcessingReportQuery{Section: "processors", Limit: 1}
			reads := 0
			wantUntil := fixture.now.Add(2 * time.Second)
			reader := processingReportReadFunc(func(_ context.Context, a value.ProcessingAuthority, q value.ProcessingReportQuery) (value.ProcessingReportPage, error) {
				reads++
				if !a.Valid(fixture.now) || q != query {
					t.Fatal("report reader received changed selection or invalid authority")
				}
				page := value.ProcessingReportPage{
					SchemaVersion: value.ProcessingReportFormat, RootID: changes.RootID, InstallationID: changes.InstallationID,
					Section: q.Section, SelectionCreatedBefore: a.ObservedAt,
					PolicyRevision: value.ProcessingReportRevision{UID: a.Policy.Revision.UID, Generation: a.Policy.Revision.Generation, Digest: hex.EncodeToString(a.Policy.Revision.Digest[:])},
					Records:        []value.ProcessingReportRecord{}, ObservedAt: a.ObservedAt, ValidUntil: a.ValidUntil,
					ProcessorDeclarations: "unsupplied", Coverage: value.ProcessingReportCoverage(),
				}
				switch name {
				case "allowed":
					fixture.i.ValidUntil = wantUntil
				case "unavailable":
					return value.ProcessingReportPage{}, value.ErrUnavailable
				case "wrong-root":
					page.RootID = processingID(99)
				case "wrong-policy":
					page.PolicyRevision.Generation++
				case "wrong-selection":
					page.SelectionCreatedBefore = page.SelectionCreatedBefore.Add(-time.Second)
				case "post-read-role-loss":
					fixture.i.Groups = nil
				case "post-read-expiry":
					fixture.now = a.ValidUntil
				}
				return page, nil
			})
			service := ProcessingReport{RootID: changes.RootID, InstallationID: changes.InstallationID, Policies: fixture, Recovery: fixture, Reports: reader, Now: changes.Now}
			if name == "invalid-section" {
				query.Section = "arbitrary-sql"
			}
			if name == "ordinary-reader" {
				fixture.i.Groups = nil
			}
			page, err := service.Get(t.Context(), fixture, query)
			if name == "allowed" {
				if err != nil || !page.Valid(query, fixture.now) || !page.ValidUntil.Equal(wantUntil) || reads != 1 || fixture.policyObservations != 1 || fixture.recoveryObservations != 1 {
					t.Fatal("report renewed authority or failed its original identity cutoff", err, reads, fixture.policyObservations, fixture.recoveryObservations)
				}
				return
			}
			want := value.ErrUnavailable
			if name == "ordinary-reader" {
				want = identity.ErrDenied
			}
			if !errors.Is(err, want) || !reflect.DeepEqual(page, value.ProcessingReportPage{}) {
				t.Fatal("report disclosed outside the selected authority and source", page, err)
			}
			if (name == "invalid-section" || name == "ordinary-reader") && reads != 0 {
				t.Fatal("report source was read before authorization")
			}
		})
	}
}
