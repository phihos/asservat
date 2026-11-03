package objectstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	"github.com/google/pprof/profile"
)

func comparisonEncryptedNative(t *testing.T, value int64) []byte {
	t.Helper()
	function := &profile.Function{ID: 1, Name: "synthetic.work"}
	location := &profile.Location{ID: 1, Line: []profile.Line{{Function: function}}}
	p := &profile.Profile{SampleType: []*profile.ValueType{{Type: "cpu", Unit: "nanoseconds"}},
		PeriodType: &profile.ValueType{Type: "cpu", Unit: "nanoseconds"}, Period: 1, DurationNanos: int64(time.Second),
		Function: []*profile.Function{function}, Location: []*profile.Location{location},
		Sample: []*profile.Sample{{Location: []*profile.Location{location}, Value: []int64{value}}}}
	var buffer bytes.Buffer
	if err := p.Write(&buffer); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// Real framing/manifest authentication and pinned TLS ranges compose with the
// actual comparison parser. The two providers, receipts and source authority
// remain synthetic; this does not qualify SQL or deployed worker operation.
func TestProfileComparisonEncryptedSources(t *testing.T) {
	for _, mode := range []string{"complete", "baseline-ciphertext", "incident-ciphertext", "baseline-whole-file-hash", "incident-whole-file-hash", "cancel-second-source", "swapped-opened"} {
		t.Run(mode, func(t *testing.T) {
			baselineDir, incidentDir := t.TempDir(), t.TempDir()
			baseline := prepareProfileEncryptedFixture(t, baselineDir, bytes.NewReader(comparisonEncryptedNative(t, 7)), mode == "baseline-whole-file-hash")
			incident := prepareProfileEncryptedFixture(t, incidentDir, bytes.NewReader(comparisonEncryptedNative(t, 11)), mode == "incident-whole-file-hash")
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			baselineOpened, _, _ := openProfileEncryptedFixture(t, ctx, baselineDir, baseline, false)
			incidentOpened, entered, unblock := openProfileEncryptedFixture(t, ctx, incidentDir, incident, mode == "cancel-second-source")
			defer unblock()
			readBaseline, readIncident := baselineOpened, incidentOpened
			if mode == "swapped-opened" {
				// Both sources are authentic, but their opened handles are
				// attached to the opposite accepted baseline/incident scopes.
				readBaseline, readIncident = incidentOpened, baselineOpened
			}
			if mode == "baseline-ciphertext" || mode == "incident-ciphertext" {
				dir := baselineDir
				if mode == "incident-ciphertext" {
					dir = incidentDir
				}
				file, err := os.OpenFile(filepath.Join(dir, "data"), os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				value := []byte{0}
				if _, err = file.ReadAt(value, 32); err != nil {
					t.Fatal(err)
				}
				value[0] ^= 1
				if _, err = file.WriteAt(value, 32); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			type result struct {
				comparison query.ProfileComparison
				err        error
			}
			done := make(chan result, 1)
			selection := query.ProfileComparisonSelection{SampleType: "cpu", Normalization: "perSecond", TopN: 20}
			go func() {
				comparison, err := evidence.ReadProfileComparison(ctx,
					evidence.ProfileComparisonSource{Opened: readBaseline, Source: baseline.Source, Scope: baseline.Scope},
					evidence.ProfileComparisonSource{Opened: readIncident, Source: incident.Source, Scope: incident.Scope},
					selection, diagnostics.ComparePprof)
				done <- result{comparison, err}
			}()
			if mode == "cancel-second-source" {
				select {
				case <-entered:
					cancel()
					unblock()
				case <-time.After(3 * time.Second):
					t.Fatal("second input was not reached")
				}
			}
			select {
			case got := <-done:
				if mode == "complete" {
					if got.err != nil || !got.comparison.Valid(selection) || len(got.comparison.Rows) != 1 || got.comparison.Rows[0].Delta != 4 {
						t.Fatal("authenticated comparison", got.comparison, got.err)
					}
				} else if got.err == nil || errors.Is(got.err, query.ErrProfileIncompatible) || got.comparison.Rows != nil {
					t.Fatal("invalid source yielded comparison", got.comparison, got.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("comparison failed to join")
			}
			for _, opened := range []*FramedNativeSource{baselineOpened, incidentOpened} {
				opened.mu.Lock()
				closed, retained := opened.closed, opened.reader != nil || len(opened.carry) != 0
				opened.mu.Unlock()
				if !closed || retained {
					t.Fatal("comparison source retained keys or plaintext")
				}
			}
		})
	}
}
