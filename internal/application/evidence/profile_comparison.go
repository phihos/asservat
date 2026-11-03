package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// ProfileComparer is the closed regional interpreter. Both files are consumed
// completely; neither raw source nor its complete function map leaves the worker.
type ProfileComparer func(context.Context, io.Reader, query.ProfileComparisonAcquisition, io.Reader, query.ProfileComparisonAcquisition, query.ProfileComparisonSelection) (query.ProfileComparison, error)

// ProfileComparisonSource carries an already opened, independently authorized
// source. These values confer no authority. The owner must retain both current
// authorizations and the original request through result delivery.
type ProfileComparisonSource struct {
	Opened NativeArtifactSource
	Source NativeContextSource
	Scope  query.ContextProjectionScope
}

// ReadProfileComparison reuses the single-source authenticated streaming reader
// for each input. It derives acquisition facts from independently pinned accepted
// expectations, never from caller assertions. Even a semantic mismatch requires
// both complete native hashes. All supplied readers close on every exit.
func ReadProfileComparison(ctx context.Context, baseline, incident ProfileComparisonSource, selection query.ProfileComparisonSelection, compare ProfileComparer) (query.ProfileComparison, error) {
	var zero query.ProfileComparison
	openedSources := [2]NativeArtifactSource{baseline.Opened, incident.Opened}
	closeSources := func() {
		for index, opened := range openedSources {
			if opened != nil {
				opened.Close()
				openedSources[index] = nil
			}
		}
	}
	defer closeSources()
	if ctx == nil || ctx.Err() != nil || compare == nil || !selection.Valid() {
		return zero, query.ErrUnavailable
	}
	var readers [2]*profileNativeReader
	var facts [2]query.ProfileComparisonAcquisition
	for index, source := range []ProfileComparisonSource{baseline, incident} {
		if source.Opened == nil || !source.Scope.Valid() || source.Scope.NativeType != artifact.PprofArtifact ||
			source.Scope.Profile.SampleType != selection.SampleType || source.Scope.Profile.TopN != selection.TopN ||
			!source.Source.Valid(source.Scope.Version) || !projectionExpectation(source.Source.Expectation, source.Scope) ||
			!source.Source.Expectation.Profile.Valid() {
			return zero, query.ErrUnavailable
		}
		metadata := source.Opened.Metadata()
		if !ValidNativeSourceMetadata(source.Source, metadata) {
			return zero, query.ErrUnavailable
		}
		acquisition := source.Source.Expectation.Profile
		facts[index] = query.ProfileComparisonAcquisition{ProfileType: acquisition.Type, Mode: acquisition.Mode, ForceGC: acquisition.ForceGC}
		if !facts[index].Valid() {
			return zero, query.ErrUnavailable
		}
		readers[index] = &profileNativeReader{ctx: ctx, source: source.Opened, size: metadata.Size}
		defer func(reader *profileNativeReader) { clear(reader.buffer) }(readers[index])
	}
	result, err := compare(ctx, readers[0], facts[0], readers[1], facts[1], selection)
	// Join and drop both opened sources before checking the original owner
	// again. Cleanup may block or coincide with request cancellation; it must
	// not turn a previously prepared result or mismatch into a late handoff.
	closeSources()
	complete := ctx.Err() == nil
	for _, reader := range readers {
		complete = complete && !reader.failed && reader.final && reader.offset == reader.size && len(reader.buffer) == 0
	}
	if !complete {
		result.Clear()
		return zero, query.ErrUnavailable
	}
	if errors.Is(err, query.ErrProfileIncompatible) {
		result.Clear()
		return zero, query.ErrProfileIncompatible
	}
	if errors.Is(err, query.ErrRecordTooLarge) {
		result.Clear()
		return zero, query.ErrRecordTooLarge
	}
	if err != nil || !result.Valid(selection) || result.Baseline.ProfileComparisonAcquisition != facts[0] || result.Incident.ProfileComparisonAcquisition != facts[1] {
		result.Clear()
		return zero, query.ErrUnavailable
	}
	encoded, err := json.Marshal(result)
	defer clear(encoded)
	if err != nil || ctx.Err() != nil {
		result.Clear()
		return zero, query.ErrUnavailable
	}
	if len(encoded) > query.ProfileComparisonBytes {
		result.Clear()
		return zero, query.ErrRecordTooLarge
	}
	return result, nil
}
